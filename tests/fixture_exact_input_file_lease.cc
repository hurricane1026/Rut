#include "fixture_exact_input_file_lease.h"

#include <algorithm>
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

namespace rut::test::fixture_exact_input_file_lease {
namespace {

constexpr unsigned kNameAttempts = 32u;
constexpr unsigned kInterruptedAttempts = 64u;

Identity make_identity(const struct stat& value) {
    return {static_cast<std::uint64_t>(value.st_dev),
            static_cast<std::uint64_t>(value.st_ino),
            static_cast<std::uint64_t>(value.st_mode),
            static_cast<std::uint64_t>(value.st_uid),
            static_cast<std::uint64_t>(value.st_gid),
            value.st_size < 0 ? 0u : static_cast<std::uint64_t>(value.st_size),
            static_cast<std::uint64_t>(value.st_nlink)};
}

bool same_inode(const struct stat& value, const Identity& expected) {
    return S_ISREG(value.st_mode) && static_cast<std::uint64_t>(value.st_dev) == expected.device &&
           static_cast<std::uint64_t>(value.st_ino) == expected.inode;
}

bool same_linked_file(const struct stat& value, const Identity& expected, bool linked) {
    return same_inode(value, expected) &&
           static_cast<std::uint64_t>(value.st_mode) == expected.mode &&
           static_cast<std::uint64_t>(value.st_uid) == expected.uid &&
           static_cast<std::uint64_t>(value.st_gid) == expected.gid && value.st_size >= 0 &&
           value.st_uid == getuid() && value.st_gid == getgid() &&
           static_cast<std::uint64_t>(value.st_size) == expected.size &&
           value.st_nlink == (linked ? 1u : 0u) && (value.st_mode & 0777) == 0600;
}

bool same_directory(const struct stat& value,
                    const fixture_private_directory_lease::Identity& expected) {
    return S_ISDIR(value.st_mode) && static_cast<std::uint64_t>(value.st_dev) == expected.device &&
           static_cast<std::uint64_t>(value.st_ino) == expected.inode &&
           static_cast<std::uint64_t>(value.st_mode) == expected.mode &&
           static_cast<std::uint64_t>(value.st_uid) == expected.uid &&
           static_cast<std::uint64_t>(value.st_gid) == expected.gid &&
           (value.st_mode & 0777) == 0700;
}

bool descriptor_flags(int descriptor, int access_mode, bool directory) {
    const int fd_flags = fcntl(descriptor, F_GETFD);
    const int status_flags = fcntl(descriptor, F_GETFL);
    return fd_flags >= 0 && (fd_flags & FD_CLOEXEC) != 0 && status_flags >= 0 &&
           (status_flags & O_ACCMODE) == access_mode &&
           (status_flags & (O_APPEND | O_ASYNC | O_NONBLOCK)) == 0 &&
           (!directory || (status_flags & O_DIRECTORY) != 0);
}

bool valid_seed(const std::string& value) {
    return value.empty() || (value.size() == 32u &&
                             value.find_first_not_of("0123456789abcdef") == std::string::npos);
}

bool random_hex(std::array<char, 33>& output) {
    std::array<unsigned char, 16> random{};
    std::size_t offset = 0u;
    unsigned attempts = 0u;
    while (offset != random.size() && attempts++ != kInterruptedAttempts) {
        const ssize_t count =
            getrandom(random.data() + offset, random.size() - offset, GRND_NONBLOCK);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || static_cast<std::size_t>(count) > random.size() - offset) return false;
        offset += static_cast<std::size_t>(count);
    }
    if (offset != random.size()) return errno = EAGAIN, false;
    constexpr char digits[] = "0123456789abcdef";
    for (std::size_t index = 0u; index != random.size(); ++index) {
        output[index * 2u] = digits[random[index] >> 4u];
        output[index * 2u + 1u] = digits[random[index] & 15u];
    }
    return true;
}

bool make_name(const char* prefix, const std::string& seed, std::string& output) {
    std::array<char, 33> random{};
    if (!seed.empty())
        std::memcpy(random.data(), seed.data(), seed.size());
    else if (!random_hex(random))
        return false;
    output = prefix;
    output.append(random.data(), 32u);
    return true;
}

int rename_noreplace(int directory, const char* old_name, const char* new_name) {
#ifdef SYS_renameat2
    return static_cast<int>(
        syscall(SYS_renameat2, directory, old_name, directory, new_name, RENAME_NOREPLACE));
#else
    (void)directory;
    (void)old_name;
    (void)new_name;
    errno = ENOSYS;
    return -1;
#endif
}

Residue observe(int directory, const std::string& name) {
    if (directory < 0 || name.empty()) return Residue::Unknown;
    struct stat value{};
    if (fstatat(directory, name.c_str(), &value, AT_SYMLINK_NOFOLLOW) == 0) return Residue::Present;
    return errno == ENOENT ? Residue::Absent : Residue::Unknown;
}

}  // namespace

ExactInputFileLease::ExactInputFileLease() : receipt_(std::make_shared<CleanupReceipt>()) {}

ExactInputFileLease::~ExactInputFileLease() {
    if (state_ != State::Empty && state_ != State::Settled) {
        Diagnostic diagnostic;
        if (!cleanup(diagnostic)) {
            std::fprintf(stderr,
                         "FAIL [#358 exact input cleanup]: state=%u phase=%u errno=%d\n",
                         static_cast<unsigned>(state_),
                         static_cast<unsigned>(diagnostic.phase),
                         diagnostic.error_number);
        }
    }
}

bool ExactInputFileLease::create(fixture_private_directory_lease::PrivateDirectoryLease& directory,
                                 const void* bytes,
                                 std::size_t size,
                                 ExactInputFileLease& lease,
                                 Diagnostic& diagnostic) {
    return lease.create_impl(directory, bytes, size, nullptr, diagnostic);
}

bool ExactInputFileLease::create_with_hooks_for_testing(
    fixture_private_directory_lease::PrivateDirectoryLease& directory,
    const void* bytes,
    std::size_t size,
    const HooksForTesting& hooks,
    ExactInputFileLease& lease,
    Diagnostic& diagnostic) {
    return lease.create_impl(directory, bytes, size, &hooks, diagnostic);
}

void ExactInputFileLease::remember(const Diagnostic& diagnostic) {
    if (receipt_->diagnostic.phase == FailurePhase::None && diagnostic.phase != FailurePhase::None)
        receipt_->diagnostic = diagnostic;
}

bool ExactInputFileLease::reject(Diagnostic& diagnostic, FailurePhase phase, int error_number) {
    diagnostic = {phase, error_number == 0 ? EIO : error_number};
    remember(diagnostic);
    return false;
}

void ExactInputFileLease::transition(State state) {
    state_ = state;
    receipt_->state = state;
}

bool ExactInputFileLease::validate_directory(Diagnostic& diagnostic) const {
    struct stat held{};
    struct stat named{};
    if (directory_fd_ < 0 || fstat(directory_fd_, &held) != 0 ||
        fstatat(AT_FDCWD, directory_path_.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
        diagnostic = {FailurePhase::Directory, directory_fd_ < 0 ? EBADF : errno};
        return false;
    }
    if (!same_directory(held, directory_identity_) || !same_directory(named, directory_identity_) ||
        !descriptor_flags(directory_fd_, O_RDONLY, true)) {
        diagnostic = {FailurePhase::Directory, ESTALE};
        return false;
    }
    return true;
}

bool ExactInputFileLease::validate_reader(bool linked, Diagnostic& diagnostic) const {
    struct stat held{};
    if (reader_fd_ < 0 || fstat(reader_fd_, &held) != 0) {
        diagnostic = {FailurePhase::Revalidate, reader_fd_ < 0 ? EBADF : errno};
        return false;
    }
    if (!same_linked_file(held, identity_, linked) ||
        !descriptor_flags(reader_fd_, O_RDONLY, false)) {
        diagnostic = {FailurePhase::Revalidate, ESTALE};
        return false;
    }
    return true;
}

bool ExactInputFileLease::validate_named(const std::string& name,
                                         bool exact_semantics,
                                         Diagnostic& diagnostic) const {
    struct stat named{};
    if (directory_fd_ < 0 ||
        fstatat(directory_fd_, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
        diagnostic = {FailurePhase::Revalidate, directory_fd_ < 0 ? EBADF : errno};
        return false;
    }
    const bool valid =
        exact_semantics ? same_linked_file(named, identity_, true) : same_inode(named, identity_);
    if (!valid) {
        diagnostic = {FailurePhase::Revalidate, ESTALE};
        return false;
    }
    return true;
}

bool ExactInputFileLease::validate_bytes(Diagnostic& diagnostic) const {
    std::array<char, 512> buffer{};
    std::size_t offset = 0u;
    while (offset != expected_bytes_.size()) {
        const std::size_t amount = std::min(buffer.size(), expected_bytes_.size() - offset);
        ssize_t count = -1;
        unsigned attempts = 0u;
        do {
            count = pread(reader_fd_, buffer.data(), amount, static_cast<off_t>(offset));
        } while (count < 0 && errno == EINTR && attempts++ != kInterruptedAttempts);
        if (count <= 0 || static_cast<std::size_t>(count) != amount ||
            std::memcmp(buffer.data(), expected_bytes_.data() + offset, amount) != 0) {
            diagnostic = {FailurePhase::Bytes, count < 0 ? errno : EINVAL};
            return false;
        }
        offset += amount;
    }
    char trailing = '\0';
    ssize_t count = -1;
    unsigned attempts = 0u;
    do {
        count = pread(reader_fd_, &trailing, 1u, static_cast<off_t>(expected_bytes_.size()));
    } while (count < 0 && errno == EINTR && attempts++ != kInterruptedAttempts);
    if (count != 0) {
        diagnostic = {FailurePhase::Bytes, count < 0 ? errno : EOVERFLOW};
        return false;
    }
    return true;
}

bool ExactInputFileLease::create_impl(
    fixture_private_directory_lease::PrivateDirectoryLease& directory,
    const void* bytes,
    std::size_t size,
    const HooksForTesting* hooks,
    Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ != State::Empty || directory_fd_ >= 0 || writer_fd_ >= 0 || reader_fd_ >= 0 ||
        bytes == nullptr || size == 0u || size > kMaximumInputBytes)
        return reject(diagnostic, FailurePhase::Argument, EINVAL);
    hooks_ = hooks == nullptr ? HooksForTesting{} : *hooks;
    if (!valid_seed(hooks_.creation_seed) || !valid_seed(hooks_.quarantine_seed))
        return reject(diagnostic, FailurePhase::Argument, EINVAL);

    fixture_private_directory_lease::Diagnostic directory_diagnostic;
    if (directory.state() != fixture_private_directory_lease::State::Owned ||
        !directory.revalidate(directory_diagnostic))
        return reject(
            diagnostic,
            FailurePhase::Directory,
            directory_diagnostic.error_number == 0 ? ESTALE : directory_diagnostic.error_number);
    directory_path_ = directory.path();
    directory_identity_ = directory.identity();
    expected_bytes_.assign(static_cast<const char*>(bytes), size);
    receipt_->path.reserve(directory_path_.size() + 80u);
    receipt_->original_basename.reserve(64u);
    receipt_->quarantine_basename.reserve(64u);

    directory_fd_ = fcntl(directory.descriptor(), F_DUPFD_CLOEXEC, 3);
    if (directory_fd_ < 0 || !validate_directory(diagnostic)) {
        if (directory_fd_ < 0) reject(diagnostic, FailurePhase::Directory, errno);
        return creation_failed(diagnostic, diagnostic);
    }
    if (hooks_.creation_fault == CreationFaultForTesting::PreOpen)
        return creation_failed({FailurePhase::Hook, ECANCELED}, diagnostic);

    bool opened = false;
    for (unsigned attempt = 0u; attempt != kNameAttempts; ++attempt) {
        if (!make_name(".rut358-input-", hooks_.creation_seed, receipt_->original_basename))
            return creation_failed({FailurePhase::Name, errno}, diagnostic);
        receipt_->path = directory_path_ + "/" + receipt_->original_basename;
        current_basename_ = receipt_->original_basename;
        if (hooks_.creation_fault == CreationFaultForTesting::Open)
            return creation_failed({FailurePhase::Open, EACCES}, diagnostic);
        writer_fd_ = openat(directory_fd_,
                            current_basename_.c_str(),
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                            0600);
        if (writer_fd_ >= 0) {
            opened = true;
            break;
        }
        if (errno != EEXIST || !hooks_.creation_seed.empty())
            return creation_failed({FailurePhase::Open, errno}, diagnostic);
    }
    if (!opened) return creation_failed({FailurePhase::Open, EEXIST}, diagnostic);
    transition(State::Creating);

    if (fchmod(writer_fd_, 0600) != 0)
        return creation_failed({FailurePhase::Identity, errno}, diagnostic);
    struct stat created{};
    if (fstat(writer_fd_, &created) != 0 || !S_ISREG(created.st_mode) ||
        created.st_uid != getuid() || created.st_gid != getgid() || created.st_nlink != 1u ||
        created.st_size != 0 || (created.st_mode & 0777) != 0600 ||
        !descriptor_flags(writer_fd_, O_WRONLY, false))
        return creation_failed({FailurePhase::Identity, errno == 0 ? ESTALE : errno}, diagnostic);
    identity_ = make_identity(created);
    identity_.size = size;
    identity_known_ = true;

    std::size_t offset = 0u;
    bool partial_injected = false;
    unsigned interrupted = 0u;
    while (offset != size) {
        if (hooks_.creation_fault == CreationFaultForTesting::WriteError ||
            (hooks_.creation_fault == CreationFaultForTesting::WritePartial && partial_injected))
            return creation_failed({FailurePhase::Write, EIO}, diagnostic);
        std::size_t amount = size - offset;
        if (hooks_.creation_fault == CreationFaultForTesting::WritePartial && !partial_injected) {
            amount = std::max<std::size_t>(1u, amount / 2u);
            partial_injected = true;
        }
        const ssize_t count = write(writer_fd_, static_cast<const char*>(bytes) + offset, amount);
        if (count < 0 && errno == EINTR && interrupted++ != kInterruptedAttempts) continue;
        if (count <= 0 || static_cast<std::size_t>(count) > amount)
            return creation_failed({FailurePhase::Write, count < 0 ? errno : EIO}, diagnostic);
        offset += static_cast<std::size_t>(count);
    }
    if (hooks_.creation_fault == CreationFaultForTesting::Sync)
        return creation_failed({FailurePhase::Sync, EIO}, diagnostic);
    if (fsync(writer_fd_) != 0) return creation_failed({FailurePhase::Sync, errno}, diagnostic);

    if (hooks_.creation_fault == CreationFaultForTesting::Reopen)
        return creation_failed({FailurePhase::Reopen, EIO}, diagnostic);
    reader_fd_ =
        openat(directory_fd_, current_basename_.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (reader_fd_ < 0) return creation_failed({FailurePhase::Reopen, errno}, diagnostic);
    if (reader_fd_ == writer_fd_)
        return creation_failed({FailurePhase::Reopen, ESTALE}, diagnostic);

    struct stat writer{};
    struct stat reader{};
    struct stat named{};
    const bool verified =
        hooks_.creation_fault != CreationFaultForTesting::Verification &&
        fstat(writer_fd_, &writer) == 0 && fstat(reader_fd_, &reader) == 0 &&
        fstatat(directory_fd_, current_basename_.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_linked_file(writer, identity_, true) && same_linked_file(reader, identity_, true) &&
        same_linked_file(named, identity_, true) && descriptor_flags(writer_fd_, O_WRONLY, false) &&
        descriptor_flags(reader_fd_, O_RDONLY, false) && validate_bytes(diagnostic);
    if (!verified)
        return creation_failed({FailurePhase::Verification,
                                diagnostic.error_number == 0 ? ESTALE : diagnostic.error_number},
                               diagnostic);

    const int closing_writer = writer_fd_;
    const int close_result = close(closing_writer);
    if (close_result != 0) return creation_failed({FailurePhase::WriterClose, errno}, diagnostic);
    if (hooks_.creation_fault == CreationFaultForTesting::WriterCloseUncertain)
        return creation_failed({FailurePhase::WriterClose, EIO}, diagnostic);
    writer_fd_ = -1;

    transition(State::Active);
    return true;
}

bool ExactInputFileLease::creation_failed(const Diagnostic& cause, Diagnostic& diagnostic) {
    diagnostic = cause;
    remember(cause);
    receipt_->attempted = true;
    if (state_ == State::Creating && identity_known_) {
        Diagnostic cleanup_diagnostic;
        (void)cleanup(cleanup_diagnostic);
    } else {
        Diagnostic close_diagnostic;
        (void)close_reader(close_diagnostic);
        (void)close_directory(close_diagnostic);
        if (state_ != State::Empty) transition(State::Unresolved);
    }
    diagnostic = cause;
    return false;
}

bool ExactInputFileLease::revalidate(Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ != State::Active && state_ != State::BindingLost)
        return reject(diagnostic, FailurePhase::Revalidate, EINVAL);
    Diagnostic local;
    const bool valid = validate_directory(local) && validate_reader(true, local) &&
                       validate_named(receipt_->original_basename, true, local) &&
                       validate_bytes(local);
    if (!valid) {
        transition(State::BindingLost);
        const FailurePhase phase =
            local.phase == FailurePhase::Bytes ? FailurePhase::Bytes : FailurePhase::Revalidate;
        return reject(diagnostic, phase, local.error_number);
    }
    transition(State::Active);
    return true;
}

void ExactInputFileLease::observe_residues() {
    const int saved = errno;
    receipt_->original_residue = observe(directory_fd_, receipt_->original_basename);
    receipt_->quarantine_residue = observe(directory_fd_, receipt_->quarantine_basename);
    errno = saved;
}

bool ExactInputFileLease::quarantine(Diagnostic& diagnostic) {
    if (!validate_directory(diagnostic))
        return reject(diagnostic, FailurePhase::Directory, diagnostic.error_number);

    std::string source =
        current_basename_.empty() ? receipt_->original_basename : current_basename_;
    Diagnostic named_diagnostic;
    if (!validate_named(source, false, named_diagnostic)) {
        source = receipt_->original_basename;
        if (!validate_named(source, false, named_diagnostic)) {
            transition(State::BindingLost);
            observe_residues();
            return reject(diagnostic, FailurePhase::Quarantine, named_diagnostic.error_number);
        }
    }

    if (hooks_.cleanup_fault == CleanupFaultForTesting::QuarantineRename &&
        !cleanup_fault_consumed_) {
        cleanup_fault_consumed_ = true;
        return reject(diagnostic, FailurePhase::Quarantine, EIO);
    }

    int rename_error = EEXIST;
    for (unsigned attempt = 0u; attempt != kNameAttempts; ++attempt) {
        if (!make_name(
                ".rut358-input-quarantine-", hooks_.quarantine_seed, receipt_->quarantine_basename))
            return reject(diagnostic, FailurePhase::Name, errno);
        if (rename_noreplace(
                directory_fd_, source.c_str(), receipt_->quarantine_basename.c_str()) == 0) {
            rename_error = 0;
            break;
        }
        rename_error = errno;
        if (rename_error != EEXIST || !hooks_.quarantine_seed.empty()) break;
    }
    if (rename_error != 0) return reject(diagnostic, FailurePhase::Quarantine, rename_error);

    if (hooks_.after_quarantine_rename != nullptr)
        hooks_.after_quarantine_rename(
            directory_fd_, source.c_str(), receipt_->quarantine_basename.c_str(), hooks_.context);
    if (!validate_named(receipt_->quarantine_basename, false, named_diagnostic)) {
        current_basename_.clear();
        transition(State::BindingLost);
        observe_residues();
        return reject(diagnostic, FailurePhase::Quarantine, ESTALE);
    }
    current_basename_ = receipt_->quarantine_basename;
    receipt_->path_quarantined = true;
    transition(State::Quarantined);
    observe_residues();
    return true;
}

bool ExactInputFileLease::finish_detached(Diagnostic& diagnostic) {
    if (!receipt_->detached_inode_proven) {
        struct stat held{};
        const int authority = reader_fd_ >= 0 ? reader_fd_ : writer_fd_;
        if (authority < 0 || fstat(authority, &held) != 0 || !same_inode(held, identity_) ||
            held.st_nlink != 0u)
            return reject(diagnostic,
                          FailurePhase::Detached,
                          authority < 0 ? EBADF : (errno == 0 ? ESTALE : errno));
        receipt_->detached_inode_proven = true;
    }

    if (hooks_.cleanup_fault == CleanupFaultForTesting::DirectorySync && !cleanup_fault_consumed_) {
        cleanup_fault_consumed_ = true;
        return reject(diagnostic, FailurePhase::DirectorySettlement, EIO);
    }
    if (fsync(directory_fd_) != 0)
        return reject(diagnostic, FailurePhase::DirectorySettlement, errno);
    observe_residues();
    if (receipt_->quarantine_residue != Residue::Absent)
        return reject(diagnostic, FailurePhase::Detached, ESTALE);

    Diagnostic close_diagnostic;
    if (!close_reader(close_diagnostic)) {
        diagnostic = close_diagnostic;
        return false;
    }
    if (!close_directory(close_diagnostic)) {
        diagnostic = close_diagnostic;
        return false;
    }
    transition(State::Settled);
    receipt_->settlement_complete = true;
    return true;
}

bool ExactInputFileLease::close_reader(Diagnostic& diagnostic) {
    diagnostic = {};
    auto close_exact = [&](int& descriptor, int access_mode, bool inject) {
        if (descriptor < 0) return true;
        struct stat held{};
        if (fstat(descriptor, &held) != 0) {
            if (errno == EBADF) {
                descriptor = -1;
                return true;
            }
            return false;
        }
        if (!same_inode(held, identity_) || !descriptor_flags(descriptor, access_mode, false)) {
            errno = ESTALE;
            return false;
        }
        const int closing = descriptor;
        if (!inject) descriptor = -1;
        const int result = close(closing);
        if (result != 0) return false;
        if (inject) {
            errno = EIO;
            return false;
        }
        return true;
    };

    const bool writer_closed = close_exact(writer_fd_, O_WRONLY, false);
    const int writer_error = errno == 0 ? EIO : errno;
    const bool inject_reader =
        hooks_.cleanup_fault == CleanupFaultForTesting::ReaderCloseUncertain &&
        !cleanup_fault_consumed_;
    if (inject_reader) cleanup_fault_consumed_ = true;
    const bool reader_closed = close_exact(reader_fd_, O_RDONLY, inject_reader);
    const int reader_error = errno == 0 ? EIO : errno;
    receipt_->descriptor_closed = writer_closed && reader_closed;
    if (!receipt_->descriptor_closed)
        return reject(diagnostic,
                      FailurePhase::DescriptorClose,
                      !writer_closed ? writer_error : reader_error);
    return true;
}

bool ExactInputFileLease::close_directory(Diagnostic& diagnostic) {
    if (directory_fd_ < 0) {
        receipt_->directory_settled = true;
        return true;
    }
    struct stat held{};
    if (fstat(directory_fd_, &held) != 0 || !same_directory(held, directory_identity_) ||
        !descriptor_flags(directory_fd_, O_RDONLY, true))
        return reject(diagnostic, FailurePhase::DirectorySettlement, errno == 0 ? ESTALE : errno);
    const int closing = directory_fd_;
    directory_fd_ = -1;
    if (close(closing) != 0) return reject(diagnostic, FailurePhase::DirectorySettlement, errno);
    receipt_->directory_settled = true;
    return true;
}

bool ExactInputFileLease::cleanup(Diagnostic& diagnostic) {
    diagnostic = {};
    receipt_->attempted = true;
    if (state_ == State::Settled) return true;
    if (state_ == State::Empty) return reject(diagnostic, FailurePhase::Argument, EINVAL);

    if (state_ != State::Quarantined && state_ != State::Detached) {
        Diagnostic semantic;
        if (state_ == State::Active && revalidate(semantic)) receipt_->semantic_validated = true;
        if (!quarantine(diagnostic)) return false;
    }
    if (state_ == State::Quarantined) {
        Diagnostic named;
        if (!validate_named(current_basename_, false, named))
            return reject(diagnostic, FailurePhase::Unlink, named.error_number);
        if (hooks_.cleanup_fault == CleanupFaultForTesting::Unlink && !cleanup_fault_consumed_) {
            cleanup_fault_consumed_ = true;
            return reject(diagnostic, FailurePhase::Unlink, EIO);
        }
        if (unlinkat(directory_fd_, current_basename_.c_str(), 0) != 0)
            return reject(diagnostic, FailurePhase::Unlink, errno);
        receipt_->exact_unlinked = true;
        transition(State::Detached);
    }
    return finish_detached(diagnostic);
}

}  // namespace rut::test::fixture_exact_input_file_lease
