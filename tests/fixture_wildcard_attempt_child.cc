#include "fixture_wildcard_attempt_child.h"

#include <array>
#include <cerrno>
#include <cstdio>
#include <exception>
#include <limits>
#include <sstream>
#include <string>
#include <thread>

#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace rut::test::fixture_wildcard_attempt_child {
namespace {

using fixture_worker_protocol::read_file;
using fixture_worker_protocol::read_proc;
using fixture_worker_protocol::same_process_identity;
using fixture_worker_protocol::wait_fd;

constexpr unsigned char kReadyByte = 0x7eu;
constexpr unsigned char kReleaseByte = 0x52u;
constexpr char kLogBytes[] = "rut377 wildcard attempt paused child\n";

void fail(Diagnostic& diagnostic, FailurePhase phase, int error_number = 0) {
    diagnostic = {phase, error_number};
}

bool safe_component(const std::string& value) {
    if (value.empty() || value == "." || value == ".." || value.size() > 128u) return false;
    for (const unsigned char byte : value)
        if (byte < 0x21u || byte > 0x7eu || byte == '/') return false;
    return true;
}

bool same_directory(const struct stat& status, const source_lease::DirectoryIdentity& expected) {
    return S_ISDIR(status.st_mode) &&
           static_cast<std::uint64_t>(status.st_dev) == expected.device &&
           static_cast<std::uint64_t>(status.st_ino) == expected.inode &&
           static_cast<std::uint64_t>(status.st_mode) == expected.mode &&
           static_cast<std::uint64_t>(status.st_uid) == expected.uid &&
           static_cast<std::uint64_t>(status.st_gid) == expected.gid &&
           (status.st_mode & 0777) == 0700;
}

bool same_regular(const struct stat& status, const source_lease::SourceIdentity& expected) {
    return S_ISREG(status.st_mode) &&
           static_cast<std::uint64_t>(status.st_dev) == expected.device &&
           static_cast<std::uint64_t>(status.st_ino) == expected.inode &&
           static_cast<std::uint64_t>(status.st_mode) == expected.mode &&
           static_cast<std::uint64_t>(status.st_uid) == expected.uid &&
           static_cast<std::uint64_t>(status.st_gid) == expected.gid && status.st_size >= 0 &&
           static_cast<std::uint64_t>(status.st_size) == expected.size &&
           (status.st_mode & 0777) == 0600 && status.st_nlink == 1;
}

source_lease::SourceIdentity source_identity(const struct stat& status) {
    return {static_cast<std::uint64_t>(status.st_dev),
            static_cast<std::uint64_t>(status.st_ino),
            static_cast<std::uint64_t>(status.st_mode),
            static_cast<std::uint64_t>(status.st_uid),
            static_cast<std::uint64_t>(status.st_gid),
            static_cast<std::uint64_t>(status.st_size)};
}

bool close_checked(int& fd) {
    if (fd < 0) return true;
    const int old = fd;
    fd = -1;
    return close(old) == 0;
}

int rename_noreplace(int directory, const char* old_name, const char* new_name) {
#ifdef SYS_renameat2
    return static_cast<int>(syscall(SYS_renameat2,
                                    directory,
                                    old_name,
                                    directory,
                                    new_name,
                                    static_cast<unsigned>(RENAME_NOREPLACE)));
#else
    (void)directory;
    (void)old_name;
    (void)new_name;
    errno = ENOSYS;
    return -1;
#endif
}

bool read_pidfd_binding(int fd, pid_t expected) {
    std::string text;
    if (fd < 0 || !read_file("/proc/self/fdinfo/" + std::to_string(fd), text, 4096)) return false;
    std::istringstream lines(text);
    std::string key;
    bool found = false;
    while (lines >> key) {
        if (key == "Pid:") {
            long value = 0;
            if (found || !(lines >> value) || value != expected) return false;
            found = true;
        }
        std::string ignored;
        std::getline(lines, ignored);
    }
    return found;
}

bool pidfd_live(int fd) {
    pollfd descriptor{fd, static_cast<short>(POLLIN | POLLERR | POLLHUP), 0};
    int result;
    do {
        result = poll(&descriptor, 1, 0);
    } while (result < 0 && errno == EINTR);
    return result == 0 && descriptor.revents == 0;
}

bool write_byte(int fd, unsigned char value) {
    for (;;) {
        const ssize_t result = write(fd, &value, 1u);
        if (result == 1) return true;
        if (result < 0 && errno == EINTR) continue;
        return false;
    }
}

bool write_byte_until(int fd, unsigned char value, std::chrono::steady_clock::time_point deadline) {
    if (!wait_fd(fd, POLLOUT, deadline)) return false;
    return write_byte(fd, value);
}

bool send_pidfd_signal(int pidfd, int signal_number) {
#ifdef SYS_pidfd_send_signal
    return syscall(SYS_pidfd_send_signal, pidfd, signal_number, nullptr, 0u) == 0;
#else
    (void)pidfd;
    (void)signal_number;
    errno = ENOSYS;
    return false;
#endif
}

bool write_all(int fd, const char* bytes, std::size_t size) {
    std::size_t offset = 0;
    while (offset != size) {
        const ssize_t result = write(fd, bytes + offset, size - offset);
        if (result > 0) {
            offset += static_cast<std::size_t>(result);
        } else if (result < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

void child_main(int ready_fd, int release_fd, pid_t parent) {
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() != parent || setpgid(0, 0) != 0 ||
        getppid() != parent || !write_byte(ready_fd, kReadyByte))
        _exit(125);
    close(ready_fd);
    unsigned char release = 0;
    for (;;) {
        const ssize_t result = read(release_fd, &release, 1u);
        if (result == 1) break;
        if (result < 0 && errno == EINTR) continue;
        _exit(124);
    }
    close(release_fd);
    _exit(release == kReleaseByte ? 0 : 123);
}

bool numeric_name(const char* name, pid_t& pid) {
    if (name == nullptr || *name == '\0') return false;
    long value = 0;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(name); *p != 0; ++p) {
        if (*p < '0' || *p > '9') return false;
        if (value > 100000000L) return false;
        value = value * 10 + (*p - '0');
    }
    if (value <= 1 || value > static_cast<long>(std::numeric_limits<pid_t>::max())) return false;
    pid = static_cast<pid_t>(value);
    return true;
}

bool proc_parent(pid_t pid, pid_t& ppid) {
    std::string stat;
    if (!read_file("/proc/" + std::to_string(pid) + "/stat", stat, 8192)) return false;
    const size_t end = stat.rfind(") ");
    if (end == std::string::npos) return false;
    std::istringstream fields(stat.substr(end + 2));
    char state = 0;
    long parent = 0;
    long group = 0;
    return (fields >> state >> parent >> group) && parent >= 0 &&
           (ppid = static_cast<pid_t>(parent), true);
}

bool random_name(std::string& result) {
    std::array<unsigned char, 12> bytes{};
    std::size_t offset = 0;
    while (offset != bytes.size()) {
        const ssize_t count =
            getrandom(bytes.data() + offset, bytes.size() - offset, GRND_NONBLOCK);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += static_cast<std::size_t>(count);
    }
    result = ".rut377-child-quarantine-";
    constexpr char hex[] = "0123456789abcdef";
    for (unsigned char byte : bytes) {
        result.push_back(hex[byte >> 4u]);
        result.push_back(hex[byte & 0xfu]);
    }
    return true;
}

}  // namespace

WildcardAttemptChildLease::WildcardAttemptChildLease()
    : cleanup_state_(std::make_shared<CleanupState>()) {}

WildcardAttemptChildLease::~WildcardAttemptChildLease() {
    // Destruction never invents a wait budget. A valid identity/pidfd permits
    // one authoritative SIGKILL attempt and a nonblocking reap; uncertainty
    // is retained as a failed observable cleanup rather than reported away.
    bool process_clean = !active_;
    Diagnostic diagnostic;
    if (active_ && pidfd_ >= 0 && validate_pidfd(true, diagnostic)) {
        ProcIdentity current;
        if (validate_identity(current, diagnostic) && send_pidfd_signal(pidfd_, SIGKILL)) {
            pollfd descriptor{pidfd_, POLLIN | POLLERR | POLLHUP, 0};
            (void)poll(&descriptor, 1, 0);
            int status = 0;
            if (waitpid(child_.pid, &status, WNOHANG) == child_.pid) {
                child_.status = status;
                child_.reaped = true;
                process_clean = true;
            }
        }
        if (!process_clean) record_cleanup(false, {FailurePhase::Cleanup, EAGAIN});
    } else if (active_) {
        record_cleanup(false, {FailurePhase::Cleanup, ESTALE});
    }
    if (log_cleanup_required_) {
        Diagnostic cleanup_diagnostic;
        const bool ok = quarantine_log(cleanup_diagnostic);
        record_cleanup(process_clean && ok, ok ? Diagnostic{} : cleanup_diagnostic);
    }
    Diagnostic close_diagnostic;
    if (!close_descriptors(close_diagnostic)) record_cleanup(false, close_diagnostic);
}

WildcardAttemptChildLease::WildcardAttemptChildLease(WildcardAttemptChildLease&& other) noexcept {
    move_from(std::move(other));
}

WildcardAttemptChildLease& WildcardAttemptChildLease::operator=(
    WildcardAttemptChildLease&& other) noexcept {
    if (this != &other) {
        if (active_ || log_cleanup_required_) std::terminate();
        move_from(std::move(other));
    }
    return *this;
}

void WildcardAttemptChildLease::move_from(WildcardAttemptChildLease&& other) noexcept {
    source_ = other.source_;
    directory_fd_ = other.directory_fd_;
    log_fd_ = other.log_fd_;
    ready_fd_ = other.ready_fd_;
    release_fd_ = other.release_fd_;
    pidfd_ = other.pidfd_;
    parent_pid_ = other.parent_pid_;
    child_ = other.child_;
    identity_ = other.identity_;
    log_basename_ = std::move(other.log_basename_);
    log_path_ = std::move(other.log_path_);
    log_identity_ = other.log_identity_;
    log_identity_known_ = other.log_identity_known_;
    log_entry_known_ = other.log_entry_known_;
    log_cleanup_required_ = other.log_cleanup_required_;
    active_ = other.active_;
    released_ = other.released_;
    cleanup_state_ = std::move(other.cleanup_state_);
    other.source_ = nullptr;
    other.directory_fd_ = other.log_fd_ = other.ready_fd_ = other.release_fd_ = other.pidfd_ = -1;
    other.active_ = other.released_ = other.log_cleanup_required_ = false;
    if (!cleanup_state_) cleanup_state_ = std::make_shared<CleanupState>();
}

bool WildcardAttemptChildLease::create(const source_lease::WildcardAttemptSourceLease& source,
                                       const std::string& log_basename,
                                       std::chrono::steady_clock::time_point deadline,
                                       WildcardAttemptChildLease& lease,
                                       Diagnostic& diagnostic) {
    return create_impl(source, log_basename, deadline, lease, diagnostic);
}

bool WildcardAttemptChildLease::create_impl(const source_lease::WildcardAttemptSourceLease& source,
                                            const std::string& log_basename,
                                            std::chrono::steady_clock::time_point deadline,
                                            WildcardAttemptChildLease& lease,
                                            Diagnostic& diagnostic) {
    diagnostic = {};
    if (lease.active_ || lease.log_cleanup_required_ || !source.active() ||
        !safe_component(log_basename) || log_basename == source.basename() ||
        std::chrono::steady_clock::now() >= deadline) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }
    lease.source_ = &source;
    lease.log_basename_ = log_basename;
    lease.log_path_ =
        source.path().substr(0, source.path().size() - source.basename().size()) + log_basename;
    if (!lease.validate_source(diagnostic)) return false;

    lease.directory_fd_ =
        open(source.path().substr(0, source.path().size() - source.basename().size() - 1).c_str(),
             O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (lease.directory_fd_ < 0) {
        fail(diagnostic, FailurePhase::Directory, errno);
        return false;
    }
    struct stat directory_status{};
    if (fstat(lease.directory_fd_, &directory_status) != 0 ||
        !same_directory(directory_status, source.directory_identity())) {
        fail(diagnostic, FailurePhase::Directory, errno == 0 ? ESTALE : errno);
        lease.close_descriptors(diagnostic);
        return false;
    }
    lease.log_fd_ = openat(lease.directory_fd_,
                           log_basename.c_str(),
                           O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                           0600);
    if (lease.log_fd_ < 0) {
        fail(diagnostic, FailurePhase::Log, errno);
        lease.close_descriptors(diagnostic);
        return false;
    }
    lease.log_entry_known_ = lease.log_cleanup_required_ = true;
    struct stat log_status{};
    if (fstat(lease.log_fd_, &log_status) != 0 || !S_ISREG(log_status.st_mode) ||
        log_status.st_uid != getuid() || log_status.st_gid != getgid() ||
        (log_status.st_mode & 0777) != 0600 || log_status.st_nlink != 1) {
        fail(diagnostic, FailurePhase::Log, errno == 0 ? EINVAL : errno);
        const bool removed = lease.quarantine_log(diagnostic);
        lease.close_descriptors(diagnostic);
        lease.record_cleanup(removed, diagnostic);
        return false;
    }
    lease.log_identity_ = source_identity(log_status);
    lease.log_identity_known_ = true;
    if (!write_all(lease.log_fd_, kLogBytes, sizeof(kLogBytes) - 1u) || fsync(lease.log_fd_) != 0) {
        fail(diagnostic, FailurePhase::Log, errno);
        const bool removed = lease.quarantine_log(diagnostic);
        lease.close_descriptors(diagnostic);
        lease.record_cleanup(removed, diagnostic);
        return false;
    }
    // Refresh the immutable identity after the payload write (size is an
    // identity field), while retaining the regular/owner/mode/link checks.
    if (fstat(lease.log_fd_, &log_status) != 0 || !S_ISREG(log_status.st_mode) ||
        log_status.st_uid != getuid() || log_status.st_gid != getgid() ||
        (log_status.st_mode & 0777) != 0600 || log_status.st_nlink != 1) {
        fail(diagnostic, FailurePhase::Log, errno == 0 ? EINVAL : errno);
        const bool removed = lease.quarantine_log(diagnostic);
        lease.close_descriptors(diagnostic);
        lease.record_cleanup(removed, diagnostic);
        return false;
    }
    lease.log_identity_ = source_identity(log_status);
    if (!lease.validate_source(diagnostic)) {
        const bool removed = lease.quarantine_log(diagnostic);
        lease.close_descriptors(diagnostic);
        lease.record_cleanup(removed, diagnostic);
        return false;
    }

    int ready[2] = {-1, -1};
    int release[2] = {-1, -1};
    if (pipe2(ready, O_CLOEXEC) != 0 || pipe2(release, O_CLOEXEC) != 0) {
        fail(diagnostic, FailurePhase::Fork, errno);
        if (ready[0] >= 0) close(ready[0]);
        if (ready[1] >= 0) close(ready[1]);
        if (release[0] >= 0) close(release[0]);
        if (release[1] >= 0) close(release[1]);
        const bool removed = lease.quarantine_log(diagnostic);
        lease.close_descriptors(diagnostic);
        lease.record_cleanup(removed, diagnostic);
        return false;
    }
    lease.parent_pid_ = getpid();
    int clone_pidfd = -1;
    clone_args args{};
    args.flags = CLONE_PIDFD;
    args.pidfd = reinterpret_cast<std::uint64_t>(&clone_pidfd);
    args.exit_signal = SIGCHLD;
#ifdef SYS_clone3
    const pid_t child = static_cast<pid_t>(syscall(SYS_clone3, &args, sizeof(args)));
#else
    const pid_t child = -1;
    errno = ENOSYS;
#endif
    if (child < 0) {
        fail(diagnostic, FailurePhase::Fork, errno);
        close(ready[0]);
        close(ready[1]);
        close(release[0]);
        close(release[1]);
        const bool removed = lease.quarantine_log(diagnostic);
        lease.close_descriptors(diagnostic);
        lease.record_cleanup(removed, diagnostic);
        return false;
    }
    if (child == 0) {
        close(ready[0]);
        close(release[1]);
        child_main(ready[1], release[0], lease.parent_pid_);
    }
    close(ready[1]);
    close(release[0]);
    lease.ready_fd_ = ready[0];
    lease.release_fd_ = release[1];
    lease.child_.pid = child;
    lease.active_ = true;
    lease.pidfd_ = clone_pidfd;
    if (lease.pidfd_ < 0 || fcntl(lease.pidfd_, F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(lease.pidfd_, F_GETFD) < 0 || (fcntl(lease.pidfd_, F_GETFD) & FD_CLOEXEC) == 0) {
        fail(diagnostic, FailurePhase::Pidfd, errno == 0 ? EINVAL : errno);
        Diagnostic cleanup_diagnostic;
        (void)lease.cleanup(deadline, cleanup_diagnostic);
        return false;
    }
    if (setpgid(child, child) != 0 && errno != EACCES) {
        fail(diagnostic, FailurePhase::Identity, errno);
        Diagnostic cleanup_diagnostic;
        (void)lease.cleanup(deadline, cleanup_diagnostic);
        return false;
    }
    if (fcntl(lease.pidfd_, F_SETFD, FD_CLOEXEC) != 0 || fcntl(lease.pidfd_, F_GETFD) < 0 ||
        (fcntl(lease.pidfd_, F_GETFD) & FD_CLOEXEC) == 0 ||
        !read_pidfd_binding(lease.pidfd_, child) || !pidfd_live(lease.pidfd_)) {
        fail(diagnostic, FailurePhase::Pidfd, errno == 0 ? EINVAL : errno);
        Diagnostic cleanup_diagnostic;
        (void)lease.cleanup(deadline, cleanup_diagnostic);
        return false;
    }
    if (!wait_fd(lease.ready_fd_, POLLIN, deadline)) {
        fail(diagnostic, FailurePhase::Readiness, ETIMEDOUT);
        Diagnostic cleanup_diagnostic;
        (void)lease.cleanup(deadline, cleanup_diagnostic);
        return false;
    }
    unsigned char ready_byte = 0;
    if (read(lease.ready_fd_, &ready_byte, 1u) != 1 || ready_byte != kReadyByte) {
        fail(diagnostic, FailurePhase::Readiness, EPROTO);
        Diagnostic cleanup_diagnostic;
        (void)lease.cleanup(deadline, cleanup_diagnostic);
        return false;
    }
    if (!close_checked(lease.ready_fd_)) {
        fail(diagnostic, FailurePhase::Close, errno == 0 ? EIO : errno);
        Diagnostic cleanup_diagnostic;
        (void)lease.cleanup(deadline, cleanup_diagnostic);
        return false;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        fail(diagnostic, FailurePhase::Readiness, ETIMEDOUT);
        Diagnostic cleanup_diagnostic;
        (void)lease.cleanup(deadline, cleanup_diagnostic);
        return false;
    }
    if (!lease.validate_paused(deadline, diagnostic)) {
        Diagnostic cleanup_diagnostic;
        (void)lease.cleanup(deadline, cleanup_diagnostic);
        return false;
    }
    return true;
}

bool WildcardAttemptChildLease::validate_source(Diagnostic& diagnostic) const {
    diagnostic = {};
    source_lease::Diagnostic source_diagnostic;
    if (source_ == nullptr || !source_->active() || !source_->revalidate(source_diagnostic)) {
        fail(diagnostic,
             FailurePhase::Source,
             source_diagnostic.error_number == 0 ? ESTALE : source_diagnostic.error_number);
        return false;
    }
    struct stat status{};
    if (source_->descriptor() < 0 || fstat(source_->descriptor(), &status) != 0 ||
        status.st_dev != static_cast<dev_t>(source_->source_identity().device) ||
        status.st_ino != static_cast<ino_t>(source_->source_identity().inode) ||
        status.st_size != static_cast<off_t>(source_->source_identity().size)) {
        fail(diagnostic, FailurePhase::Source, errno == 0 ? ESTALE : errno);
        return false;
    }
    return true;
}

bool WildcardAttemptChildLease::validate_pidfd(bool require_live, Diagnostic& diagnostic) const {
    diagnostic = {};
    if (pidfd_ < 0 || fcntl(pidfd_, F_GETFD) < 0 || (fcntl(pidfd_, F_GETFD) & FD_CLOEXEC) == 0 ||
        !read_pidfd_binding(pidfd_, child_.pid) || (require_live && !pidfd_live(pidfd_))) {
        fail(diagnostic, FailurePhase::Pidfd, errno == 0 ? ESTALE : errno);
        return false;
    }
    return true;
}

bool WildcardAttemptChildLease::validate_identity(ProcIdentity& current,
                                                  Diagnostic& diagnostic) const {
    diagnostic = {};
    if (!read_proc(child_.pid, current, false) || !same_process_identity(current, identity_)) {
        fail(diagnostic, FailurePhase::Identity, ESTALE);
        return false;
    }
    return true;
}

bool WildcardAttemptChildLease::validate_paused(std::chrono::steady_clock::time_point deadline,
                                                Diagnostic& diagnostic) {
    diagnostic = {};
    if (!active_ || !validate_pidfd(true, diagnostic)) return false;
    ProcIdentity current;
    if (!read_proc(child_.pid, current, false)) {
        fail(diagnostic, FailurePhase::Identity, ESTALE);
        return false;
    }
    if (current.ppid != parent_pid_ || current.pgid != child_.pid || current.pid != child_.pid ||
        current.uid != getuid() || current.gid != getgid()) {
        fail(diagnostic, FailurePhase::Identity, ESTALE);
        return false;
    }
    ProcIdentity parent;
    if (!read_proc(parent_pid_, parent, false) || current.sid != parent.sid ||
        current.netns != parent.netns) {
        fail(diagnostic, FailurePhase::Identity, ESTALE);
        return false;
    }
    identity_ = current;
    for (;;) {
        if (!scan_direct_children(deadline, diagnostic)) return false;
        if (std::chrono::steady_clock::now() >= deadline) {
            fail(diagnostic, FailurePhase::Readiness, ETIMEDOUT);
            return false;
        }
        // The release pipe remains empty and the child is re-read after a
        // scheduling boundary, proving it did not merely flash ready. The
        // zero-time poll cannot overrun the caller's absolute deadline.
        std::this_thread::yield();
        if (std::chrono::steady_clock::now() >= deadline) {
            fail(diagnostic, FailurePhase::Readiness, ETIMEDOUT);
            return false;
        }
        pollfd child_wait{pidfd_, POLLIN | POLLERR | POLLHUP, 0};
        const int result = poll(&child_wait, 1, 0);
        if (result < 0 && errno == EINTR) continue;
        if (result > 0) {
            fail(diagnostic, FailurePhase::Readiness, ECHILD);
            return false;
        }
        if (!validate_pidfd(true, diagnostic) || !validate_identity(current, diagnostic))
            return false;
        identity_ = current;
        return true;
    }
}

bool WildcardAttemptChildLease::scan_direct_children(std::chrono::steady_clock::time_point deadline,
                                                     Diagnostic& diagnostic) const {
    diagnostic = {};
    DIR* directory = opendir("/proc");
    if (directory == nullptr) {
        fail(diagnostic, FailurePhase::Proc, errno);
        return false;
    }
    for (;;) {
        if (std::chrono::steady_clock::now() >= deadline) {
            closedir(directory);
            fail(diagnostic, FailurePhase::Proc, ETIMEDOUT);
            return false;
        }
        errno = 0;
        dirent* entry = readdir(directory);
        if (entry == nullptr) {
            const int error_number = errno;
            closedir(directory);
            if (error_number != 0) fail(diagnostic, FailurePhase::Proc, error_number);
            return error_number == 0;
        }
        pid_t pid = -1;
        if (!numeric_name(entry->d_name, pid)) continue;
        pid_t candidate_parent = -1;
        // Any unreadable/racing process record is a fail-closed observation;
        // a process that is demonstrably gone is the only safe exception.
        errno = 0;
        if (!proc_parent(pid, candidate_parent)) {
            closedir(directory);
            fail(diagnostic, FailurePhase::Proc, ESTALE);
            return false;
        }
        if (candidate_parent != parent_pid_) continue;
        ProcIdentity candidate;
        if (!read_proc(pid, candidate, false)) {
            closedir(directory);
            fail(diagnostic, FailurePhase::Proc, ESTALE);
            return false;
        }
        if (!same_process_identity(candidate, identity_)) {
            closedir(directory);
            fail(diagnostic, FailurePhase::Proc, ECHILD);
            return false;
        }
    }
}

bool WildcardAttemptChildLease::reap_until(std::chrono::steady_clock::time_point deadline,
                                           Diagnostic& diagnostic) {
    diagnostic = {};
    while (!child_.reaped) {
        int status = 0;
        const pid_t result = waitpid(child_.pid, &status, WNOHANG);
        if (result == child_.pid) {
            child_.status = status;
            child_.reaped = true;
            break;
        }
        if (result < 0 && errno != EINTR) {
            fail(diagnostic, FailurePhase::Cleanup, errno);
            return false;
        }
        if (!wait_fd(pidfd_, POLLIN, deadline)) {
            fail(diagnostic, FailurePhase::Cleanup, ETIMEDOUT);
            return false;
        }
    }
    return true;
}

bool WildcardAttemptChildLease::release(std::chrono::steady_clock::time_point deadline,
                                        Diagnostic& diagnostic) {
    diagnostic = {};
    if (!active_ || released_) {
        fail(diagnostic, FailurePhase::Argument, EALREADY);
        return false;
    }
    if (!validate_source(diagnostic) || !validate_pidfd(true, diagnostic)) return false;
    ProcIdentity expected = identity_;
    ProcIdentity current;
    if (!validate_identity(current, diagnostic) || !same_process_identity(current, expected)) {
        fail(diagnostic, FailurePhase::Identity, ESTALE);
        return false;
    }
    if (!scan_direct_children(deadline, diagnostic) || !validate_source(diagnostic) ||
        !validate_pidfd(true, diagnostic) || !validate_identity(current, diagnostic) ||
        !write_byte_until(release_fd_, kReleaseByte, deadline)) {
        if (diagnostic.phase == FailurePhase::None)
            fail(diagnostic, FailurePhase::Release, errno == 0 ? ETIMEDOUT : errno);
        return false;
    }
    released_ = true;
    const bool release_closed = close_checked(release_fd_);
    if (!reap_until(deadline, diagnostic) || !WIFEXITED(child_.status) ||
        WEXITSTATUS(child_.status) != 0) {
        if (diagnostic.phase == FailurePhase::None) fail(diagnostic, FailurePhase::Release, ECHILD);
        return false;
    }
    active_ = false;
    if (!release_closed) {
        fail(diagnostic, FailurePhase::Close, errno == 0 ? EIO : errno);
        return false;
    }
    if (pidfd_ >= 0 && close(pidfd_) != 0) {
        pidfd_ = -1;
        fail(diagnostic, FailurePhase::Close, errno);
        return false;
    }
    pidfd_ = -1;
    return true;
}

bool WildcardAttemptChildLease::cleanup(std::chrono::steady_clock::time_point deadline,
                                        Diagnostic& diagnostic) {
    diagnostic = {};
    const auto fail_cleanup = [&](const Diagnostic& failure) {
        diagnostic = failure;
        record_cleanup(false, failure);
        return false;
    };
    if (source_ == nullptr || !validate_source(diagnostic)) return fail_cleanup(diagnostic);
    if (active_) {
        if (!validate_pidfd(true, diagnostic)) {
            // A child may have died before the caller got to cleanup. A valid
            // but signalled pidfd is sufficient to reap it; an invalid or
            // replaced descriptor remains a hard fail-closed condition.
            int status = 0;
            const pid_t waited = waitpid(child_.pid, &status, WNOHANG);
            if (waited == child_.pid) {
                child_.status = status;
                child_.reaped = true;
            } else {
                Diagnostic dead_diagnostic;
                if (!validate_pidfd(false, dead_diagnostic) || pidfd_live(pidfd_))
                    return fail_cleanup(diagnostic);
                if (!reap_until(deadline, diagnostic)) return fail_cleanup(diagnostic);
            }
        } else {
            ProcIdentity current;
            if (!validate_identity(current, diagnostic)) {
                int status = 0;
                const pid_t waited = waitpid(child_.pid, &status, WNOHANG);
                if (waited == child_.pid) {
                    child_.status = status;
                    child_.reaped = true;
                } else {
                    if (!wait_fd(pidfd_, POLLIN, deadline)) return fail_cleanup(diagnostic);
                    if (!reap_until(deadline, diagnostic)) return fail_cleanup(diagnostic);
                }
                active_ = false;
                released_ = false;
                if (!cleanup_log(diagnostic)) return fail_cleanup(diagnostic);
                record_cleanup(true, diagnostic);
                return true;
            }
            if (!send_pidfd_signal(pidfd_, SIGTERM) && errno != ESRCH) {
                fail(diagnostic, FailurePhase::Cleanup, errno);
                return fail_cleanup(diagnostic);
            }
            int status = 0;
            const pid_t immediate = waitpid(child_.pid, &status, WNOHANG);
            if (immediate == child_.pid) {
                child_.status = status;
                child_.reaped = true;
            } else if (immediate == 0) {
                if (!send_pidfd_signal(pidfd_, SIGKILL) && errno != ESRCH) {
                    fail(diagnostic, FailurePhase::Cleanup, errno);
                    return fail_cleanup(diagnostic);
                }
                if (!reap_until(deadline, diagnostic)) return fail_cleanup(diagnostic);
            } else if (errno != EINTR) {
                fail(diagnostic, FailurePhase::Cleanup, errno);
                return fail_cleanup(diagnostic);
            }
        }
        active_ = false;
        released_ = false;
    }
    if (!cleanup_log(diagnostic)) return fail_cleanup(diagnostic);
    record_cleanup(true, diagnostic);
    return true;
}

bool WildcardAttemptChildLease::cleanup_log(Diagnostic& diagnostic) {
    if (!log_cleanup_required_) return true;
    if (log_fd_ >= 0) {
        struct stat current{};
        if (!log_identity_known_ || fstat(log_fd_, &current) != 0 ||
            !same_regular(current, log_identity_)) {
            fail(diagnostic, FailurePhase::Cleanup, errno == 0 ? ESTALE : errno);
            return false;
        }
        if (fsync(log_fd_) != 0) {
            fail(diagnostic, FailurePhase::Close, errno);
            return false;
        }
        if (!close_checked(log_fd_)) {
            fail(diagnostic, FailurePhase::Close, errno);
            return false;
        }
    }
    return quarantine_log(diagnostic);
}

bool WildcardAttemptChildLease::quarantine_log(Diagnostic& diagnostic) {
    diagnostic = {};
    if (!log_cleanup_required_ || !log_entry_known_ || directory_fd_ < 0) return true;
    struct stat directory{};
    if (fstat(directory_fd_, &directory) != 0 ||
        !same_directory(directory, source_->directory_identity())) {
        fail(diagnostic, FailurePhase::Directory, errno == 0 ? ESTALE : errno);
        return false;
    }
    std::string quarantine;
    int rename_error = EEXIST;
    for (unsigned attempt = 0; attempt != 32u; ++attempt) {
        if (!random_name(quarantine)) {
            fail(diagnostic, FailurePhase::Cleanup, errno == 0 ? EIO : errno);
            return false;
        }
        if (rename_noreplace(directory_fd_, log_basename_.c_str(), quarantine.c_str()) == 0) {
            rename_error = 0;
            break;
        }
        rename_error = errno;
        if (rename_error != EEXIST) break;
    }
    if (rename_error != 0) {
        fail(diagnostic, FailurePhase::Cleanup, rename_error);
        return false;
    }
    struct stat moved{};
    const bool stated =
        fstatat(directory_fd_, quarantine.c_str(), &moved, AT_SYMLINK_NOFOLLOW) == 0;
    if (!stated || !log_identity_known_ || !same_regular(moved, log_identity_)) {
        const int mismatch = stated ? ESTALE : errno;
        const int restored =
            rename_noreplace(directory_fd_, quarantine.c_str(), log_basename_.c_str());
        if (restored != 0) {
            fail(diagnostic, FailurePhase::Cleanup, errno);
            return false;
        }
        (void)fsync(directory_fd_);
        fail(diagnostic, FailurePhase::Cleanup, mismatch);
        return false;
    }
    if (unlinkat(directory_fd_, quarantine.c_str(), 0) != 0) {
        fail(diagnostic, FailurePhase::Cleanup, errno);
        return false;
    }
    if (fsync(directory_fd_) != 0) {
        fail(diagnostic, FailurePhase::Cleanup, errno);
        return false;
    }
    log_cleanup_required_ = false;
    log_entry_known_ = false;
    return true;
}

bool WildcardAttemptChildLease::close_descriptors(Diagnostic& diagnostic) {
    diagnostic = {};
    bool ok = true;
    if (!close_checked(ready_fd_)) {
        fail(diagnostic, FailurePhase::Close, errno);
        ok = false;
    }
    if (!close_checked(release_fd_)) {
        if (ok) fail(diagnostic, FailurePhase::Close, errno);
        ok = false;
    }
    if (!close_checked(pidfd_)) {
        if (ok) fail(diagnostic, FailurePhase::Close, errno);
        ok = false;
    }
    if (!close_checked(log_fd_)) {
        if (ok) fail(diagnostic, FailurePhase::Close, errno);
        ok = false;
    }
    if (!close_checked(directory_fd_)) {
        if (ok) fail(diagnostic, FailurePhase::Close, errno);
        ok = false;
    }
    return ok;
}

void WildcardAttemptChildLease::record_cleanup(bool succeeded, const Diagnostic& diagnostic) {
    if (!cleanup_state_->attempted) {
        cleanup_state_->attempted = true;
        cleanup_state_->succeeded = succeeded;
        cleanup_state_->diagnostic = diagnostic;
    } else if (!succeeded && cleanup_state_->succeeded) {
        cleanup_state_->succeeded = false;
        cleanup_state_->diagnostic = diagnostic;
    }
}

}  // namespace rut::test::fixture_wildcard_attempt_child
