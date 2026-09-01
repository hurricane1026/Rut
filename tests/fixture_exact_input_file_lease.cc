#include "fixture_exact_input_file_lease.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <limits>

#include <fcntl.h>
#include <linux/fs.h>
#include <linux/kcmp.h>
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
           static_cast<std::uint64_t>(value.st_size) == expected.size &&
           value.st_nlink == (linked ? 1u : 0u) && (value.st_mode & 0777) == 0600;
}

int ordinary_kcmp(int first, int second) {
#ifdef SYS_kcmp
    return static_cast<int>(syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE, first, second));
#else
    (void)first;
    (void)second;
    errno = ENOSYS;
    return -1;
#endif
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
    if (state_ != State::Empty && state_ != State::Settled && state_ != State::Unresolved) {
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
    if (state_ == State::Settled) return;
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
        !descriptor_flags(reader_fd_, O_RDONLY, false) ||
        !validate_private_authorities(linked, diagnostic) ||
        !same_open_file_description(reader_fd_, authority_one_fd_, diagnostic) ||
        !same_open_file_description(reader_fd_, authority_two_fd_, diagnostic)) {
        if (diagnostic.phase != FailurePhase::None) return false;
        diagnostic = {FailurePhase::Revalidate, ESTALE};
        return false;
    }
    return true;
}

bool ExactInputFileLease::same_open_file_description(int first,
                                                     int second,
                                                     Diagnostic& diagnostic) const {
    diagnostic = {};
    errno = 0;
    const int compared = hooks_.kcmp == nullptr ? ordinary_kcmp(first, second)
                                                : hooks_.kcmp(first, second, hooks_.context);
    const int comparison_error = errno == 0 ? EIO : errno;
    if (compared == 0) return true;
    diagnostic = {FailurePhase::Revalidate, compared > 0 ? EXDEV : comparison_error};
    return false;
}

bool ExactInputFileLease::validate_private_authorities(bool linked, Diagnostic& diagnostic) const {
    struct stat first{};
    struct stat second{};
    if (authority_one_fd_ < 0 || authority_two_fd_ < 0 || fstat(authority_one_fd_, &first) != 0 ||
        fstat(authority_two_fd_, &second) != 0 || !same_linked_file(first, identity_, linked) ||
        !same_linked_file(second, identity_, linked) ||
        !descriptor_flags(authority_one_fd_, O_RDONLY, false) ||
        !descriptor_flags(authority_two_fd_, O_RDONLY, false)) {
        diagnostic = {FailurePhase::Revalidate, errno == 0 ? ESTALE : errno};
        return false;
    }
    return same_open_file_description(authority_one_fd_, authority_two_fd_, diagnostic);
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
        authority_one_fd_ >= 0 || authority_two_fd_ >= 0 || bytes == nullptr || size == 0u ||
        size > kMaximumInputBytes)
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

    // Capture the created inode immediately.  Every later failure therefore
    // has an exact descriptor and dev/inode authority for cleanup.
    struct stat created{};
    if (fstat(writer_fd_, &created) != 0 || !S_ISREG(created.st_mode) || created.st_nlink != 1u ||
        created.st_size != 0 || !descriptor_flags(writer_fd_, O_WRONLY, false))
        return creation_failed({FailurePhase::Identity, errno == 0 ? ESTALE : errno}, diagnostic);
    identity_ = make_identity(created);
    identity_known_ = true;
    if (hooks_.creation_fault == CreationFaultForTesting::Identity)
        return creation_failed({FailurePhase::Identity, EIO}, diagnostic);
    if (fchmod(writer_fd_, 0600) != 0)
        return creation_failed({FailurePhase::Identity, errno}, diagnostic);
    if (fstat(writer_fd_, &created) != 0 || !S_ISREG(created.st_mode) ||
        !same_inode(created, identity_) || created.st_nlink != 1u || created.st_size != 0 ||
        (created.st_mode & 0777) != 0600 || !descriptor_flags(writer_fd_, O_WRONLY, false))
        return creation_failed({FailurePhase::Identity, errno == 0 ? ESTALE : errno}, diagnostic);
    identity_ = make_identity(created);

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
    if (fstat(writer_fd_, &created) != 0 || !same_inode(created, identity_) ||
        created.st_size < 0 || static_cast<std::size_t>(created.st_size) != size ||
        created.st_nlink != 1u || (created.st_mode & 0777) != 0600)
        return creation_failed({FailurePhase::Verification, errno == 0 ? ESTALE : errno},
                               diagnostic);
    identity_ = make_identity(created);

    if (hooks_.creation_fault == CreationFaultForTesting::Reopen)
        return creation_failed({FailurePhase::Reopen, EIO}, diagnostic);
    reader_fd_ =
        openat(directory_fd_, current_basename_.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (reader_fd_ < 0) return creation_failed({FailurePhase::Reopen, errno}, diagnostic);
    if (reader_fd_ == writer_fd_)
        return creation_failed({FailurePhase::Reopen, ESTALE}, diagnostic);
    authority_one_fd_ = fcntl(reader_fd_, F_DUPFD_CLOEXEC, 3);
    if (authority_one_fd_ < 0) return creation_failed({FailurePhase::Reopen, errno}, diagnostic);
    authority_two_fd_ = fcntl(reader_fd_, F_DUPFD_CLOEXEC, 3);
    if (authority_two_fd_ < 0) return creation_failed({FailurePhase::Reopen, errno}, diagnostic);

    struct stat writer{};
    struct stat reader{};
    struct stat named{};
    const bool verified =
        hooks_.creation_fault != CreationFaultForTesting::Verification &&
        fstat(writer_fd_, &writer) == 0 && fstat(reader_fd_, &reader) == 0 &&
        fstatat(directory_fd_, current_basename_.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_linked_file(writer, identity_, true) && same_linked_file(reader, identity_, true) &&
        same_linked_file(named, identity_, true) && descriptor_flags(writer_fd_, O_WRONLY, false) &&
        descriptor_flags(reader_fd_, O_RDONLY, false) &&
        validate_private_authorities(true, diagnostic) &&
        same_open_file_description(reader_fd_, authority_one_fd_, diagnostic) &&
        same_open_file_description(reader_fd_, authority_two_fd_, diagnostic) &&
        validate_bytes(diagnostic);
    if (!verified)
        return creation_failed({FailurePhase::Verification,
                                diagnostic.error_number == 0 ? ESTALE : diagnostic.error_number},
                               diagnostic);

    Diagnostic close_diagnostic;
    if (!close_one(writer_fd_, DescriptorRole::Writer, receipt_->writer_close, close_diagnostic))
        return creation_failed({FailurePhase::WriterClose, close_diagnostic.error_number},
                               diagnostic);

    active_published_ = true;
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
    if (state_ == State::Settled) {
        diagnostic = {FailurePhase::Revalidate, EALREADY};
        return false;
    }
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

bool ExactInputFileLease::resolve_descriptor_custody(Diagnostic& diagnostic) {
    diagnostic = {};
    if (custody_resolved_) return true;
    if (state_ == State::Creating) return true;

    if (!custody_hook_consumed_) {
        custody_hook_consumed_ = true;
        if (hooks_.before_cleanup_custody != nullptr)
            hooks_.before_cleanup_custody(
                reader_fd_, authority_one_fd_, authority_two_fd_, hooks_.context);
    }

    const std::array<int, 3> descriptors = {reader_fd_, authority_one_fd_, authority_two_fd_};
    for (const int descriptor : descriptors) {
        if (descriptor < 0 || fcntl(descriptor, F_GETFD) < 0)
            return reject(diagnostic,
                          FailurePhase::DescriptorClose,
                          descriptor < 0 ? EBADF : (errno == 0 ? EIO : errno));
    }

    enum class Relation : std::uint8_t { Different, Same };
    std::array<std::array<Relation, 3>, 3> relations{};
    unsigned same_edges = 0u;
    for (std::size_t first = 0u; first != descriptors.size(); ++first) {
        for (std::size_t second = first + 1u; second != descriptors.size(); ++second) {
            Diagnostic relation;
            if (same_open_file_description(descriptors[first], descriptors[second], relation)) {
                relations[first][second] = Relation::Same;
                ++same_edges;
            } else if (relation.error_number == EXDEV) {
                relations[first][second] = Relation::Different;
            } else {
                return reject(diagnostic,
                              FailurePhase::DescriptorClose,
                              relation.error_number == 0 ? EIO : relation.error_number);
            }
        }
    }

    original_members_ = {};
    if (same_edges == 3u) {
        original_members_.fill(true);
    } else if (same_edges == 1u) {
        for (std::size_t first = 0u; first != descriptors.size(); ++first)
            for (std::size_t second = first + 1u; second != descriptors.size(); ++second)
                if (relations[first][second] == Relation::Same) {
                    original_members_[first] = true;
                    original_members_[second] = true;
                }
    } else {
        // Zero same edges has no original majority. Two same edges violates
        // equivalence transitivity. Both are outside the one-replacement
        // boundary and must leave every numeric slot untouched.
        original_members_ = {};
        return reject(diagnostic, FailurePhase::DescriptorClose, ESTALE);
    }

    for (std::size_t index = 0u; index != descriptors.size(); ++index) {
        if (!original_members_[index]) continue;
        struct stat held{};
        if (fstat(descriptors[index], &held) != 0 || !same_linked_file(held, identity_, true) ||
            !descriptor_flags(descriptors[index], O_RDONLY, false)) {
            original_members_ = {};
            return reject(diagnostic, FailurePhase::DescriptorClose, errno == 0 ? ESTALE : errno);
        }
    }

    std::array<int*, 3> slots = {&reader_fd_, &authority_one_fd_, &authority_two_fd_};
    std::array<bool*, 3> preserved = {&receipt_->foreign_reader_preserved,
                                      &receipt_->foreign_authority_one_preserved,
                                      &receipt_->foreign_authority_two_preserved};
    for (std::size_t index = 0u; index != slots.size(); ++index) {
        if (original_members_[index]) continue;
        // The two-member exact-OFD majority proves this sole nonmember foreign.
        // Relinquish the numeric slot without inspecting or closing it again.
        *slots[index] = -1;
        *preserved[index] = true;
    }
    custody_resolved_ = true;
    return true;
}

int ExactInputFileLease::proven_original_descriptor() const {
    const std::array<int, 3> descriptors = {reader_fd_, authority_one_fd_, authority_two_fd_};
    for (std::size_t index = 0u; index != descriptors.size(); ++index)
        if (original_members_[index] && descriptors[index] >= 0) return descriptors[index];
    return -1;
}

bool ExactInputFileLease::finish_detached(Diagnostic& diagnostic) {
    if (!receipt_->detached_inode_proven) {
        struct stat held{};
        const int authority =
            custody_resolved_
                ? proven_original_descriptor()
                : (authority_one_fd_ >= 0 ? authority_one_fd_
                                          : (reader_fd_ >= 0 ? reader_fd_ : writer_fd_));
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
    if (receipt_->original_residue != Residue::Absent ||
        receipt_->quarantine_residue != Residue::Absent)
        return reject(diagnostic,
                      FailurePhase::Detached,
                      receipt_->original_residue == Residue::Present ||
                              receipt_->quarantine_residue == Residue::Present
                          ? EEXIST
                          : ESTALE);

    Diagnostic close_diagnostic;
    const bool descriptors_closed = close_reader(close_diagnostic);
    const Diagnostic descriptor_diagnostic = close_diagnostic;
    const bool close_uncertain =
        receipt_->writer_close.uncertain || receipt_->reader_close.uncertain ||
        receipt_->authority_one_close.uncertain || receipt_->authority_two_close.uncertain;
    const bool directory_closed =
        descriptors_closed || close_uncertain ? close_directory(close_diagnostic) : false;
    if (!descriptors_closed || !directory_closed) {
        diagnostic = !descriptors_closed ? descriptor_diagnostic : close_diagnostic;
        if (close_uncertain || receipt_->directory_close.uncertain) transition(State::Unresolved);
        return false;
    }
    transition(State::Settled);
    receipt_->settlement_complete = true;
    return true;
}

bool ExactInputFileLease::close_one(int& descriptor,
                                    DescriptorRole role,
                                    CloseOutcome& outcome,
                                    Diagnostic& diagnostic) {
    diagnostic = {};
    if (outcome.attempted) {
        if (outcome.succeeded) return true;
        diagnostic = {role == DescriptorRole::Directory ? FailurePhase::DirectorySettlement
                                                        : FailurePhase::DescriptorClose,
                      outcome.error_number == 0 ? EIO : outcome.error_number};
        return false;
    }
    if (descriptor < 0) return true;
    const int closing = descriptor;
    descriptor = -1;  // A real close is one-shot even when its result is uncertain.
    outcome.attempts = 1u;
    outcome.attempted = true;
    errno = 0;
    const int result =
        hooks_.close == nullptr ? close(closing) : hooks_.close(closing, role, hooks_.context);
    int error = errno == 0 ? EIO : errno;
    const bool inject = (role == DescriptorRole::Writer &&
                         hooks_.creation_fault == CreationFaultForTesting::WriterCloseUncertain) ||
                        (role == DescriptorRole::Reader &&
                         hooks_.cleanup_fault == CleanupFaultForTesting::ReaderCloseUncertain &&
                         !cleanup_fault_consumed_);
    if (inject) {
        cleanup_fault_consumed_ = true;
        error = EIO;
    }
    if (result == 0 && !inject) {
        outcome.succeeded = true;
        return true;
    }
    outcome.uncertain = true;
    outcome.error_number = error;
    diagnostic = {role == DescriptorRole::Directory ? FailurePhase::DirectorySettlement
                                                    : FailurePhase::DescriptorClose,
                  error};
    return false;
}

bool ExactInputFileLease::close_reader(Diagnostic& diagnostic) {
    diagnostic = {};
    std::array<int*, 3> slots = {&reader_fd_, &authority_one_fd_, &authority_two_fd_};
    const std::array<int, 3> descriptors = {reader_fd_, authority_one_fd_, authority_two_fd_};
    std::array<bool, 3> original_members = original_members_;
    unsigned live = 0u;
    for (const int descriptor : descriptors)
        if (descriptor >= 0) ++live;

    int comparison_error = 0;
    unsigned same_edges = 0u;
    if (custody_resolved_) {
        // The all-pairs proof was completed before namespace mutation. Any
        // foreign numeric slot has already been relinquished without close.
    } else if (!active_published_) {
        // Creation has never published a borrowed descriptor. Every live
        // reader/authority slot is still exclusively internal and owned even
        // after namespace state advances to Detached during rollback.
        for (std::size_t index = 0u; index != descriptors.size(); ++index)
            original_members[index] = descriptors[index] >= 0;
    } else if (live != 0u) {
        for (std::size_t first = 0u; first != descriptors.size(); ++first) {
            if (descriptors[first] < 0) continue;
            for (std::size_t second = first + 1u; second != descriptors.size(); ++second) {
                if (descriptors[second] < 0) continue;
                Diagnostic relation;
                if (same_open_file_description(descriptors[first], descriptors[second], relation)) {
                    original_members[first] = true;
                    original_members[second] = true;
                    ++same_edges;
                } else if (relation.error_number != EXDEV && comparison_error == 0) {
                    comparison_error = relation.error_number;
                }
            }
        }
        if (same_edges == 0u)
            return reject(diagnostic,
                          FailurePhase::DescriptorClose,
                          comparison_error == 0 ? ESTALE : comparison_error);
    }

    for (std::size_t index = 0u; !custody_resolved_ && index != slots.size(); ++index) {
        if (*slots[index] < 0 || original_members[index]) continue;
        // Under the documented at-most-one replacement boundary, the exact
        // two-member OFD majority proves every nonmember foreign. Consume its
        // numeric slot without closing it.
        *slots[index] = -1;
        if (index == 0u)
            receipt_->foreign_reader_preserved = true;
        else if (index == 1u)
            receipt_->foreign_authority_one_preserved = true;
        else
            receipt_->foreign_authority_two_preserved = true;
    }

    Diagnostic first_failure;
    auto close_role = [&](int& descriptor, DescriptorRole role, CloseOutcome& outcome) {
        Diagnostic local;
        const bool closed = close_one(descriptor, role, outcome, local);
        if (!closed && first_failure.phase == FailurePhase::None) first_failure = local;
        return closed;
    };
    const bool writer_closed =
        close_role(writer_fd_, DescriptorRole::Writer, receipt_->writer_close);
    const bool reader_closed =
        !original_members[0] ||
        close_role(reader_fd_, DescriptorRole::Reader, receipt_->reader_close);
    const bool first_closed =
        !original_members[1] ||
        close_role(authority_one_fd_, DescriptorRole::AuthorityOne, receipt_->authority_one_close);
    const bool second_closed =
        !original_members[2] ||
        close_role(authority_two_fd_, DescriptorRole::AuthorityTwo, receipt_->authority_two_close);
    const bool reader_settled =
        original_members[0]
            ? reader_closed
            : (custody_resolved_ ? receipt_->foreign_reader_preserved : reader_closed);
    const bool first_settled =
        original_members[1]
            ? first_closed
            : (custody_resolved_ ? receipt_->foreign_authority_one_preserved : first_closed);
    const bool second_settled =
        original_members[2]
            ? second_closed
            : (custody_resolved_ ? receipt_->foreign_authority_two_preserved : second_closed);
    receipt_->descriptor_closed =
        writer_closed && reader_settled && first_settled && second_settled;
    if (!receipt_->descriptor_closed) {
        diagnostic = first_failure.phase == FailurePhase::None
                         ? Diagnostic{FailurePhase::DescriptorClose, EIO}
                         : first_failure;
        remember(diagnostic);
        return false;
    }
    return true;
}

bool ExactInputFileLease::close_directory(Diagnostic& diagnostic) {
    if (directory_fd_ < 0) {
        if (!receipt_->directory_close.attempted || receipt_->directory_close.succeeded) {
            receipt_->directory_settled = true;
            return true;
        }
        diagnostic = {FailurePhase::DirectorySettlement,
                      receipt_->directory_close.error_number == 0
                          ? EIO
                          : receipt_->directory_close.error_number};
        return false;
    }
    struct stat held{};
    if (fstat(directory_fd_, &held) != 0 || !same_directory(held, directory_identity_) ||
        !descriptor_flags(directory_fd_, O_RDONLY, true))
        return reject(diagnostic, FailurePhase::DirectorySettlement, errno == 0 ? ESTALE : errno);
    if (!close_one(
            directory_fd_, DescriptorRole::Directory, receipt_->directory_close, diagnostic)) {
        remember(diagnostic);
        return false;
    }
    receipt_->directory_settled = true;
    return true;
}

bool ExactInputFileLease::cleanup(Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ == State::Settled) return true;
    receipt_->attempted = true;
    if (state_ == State::Empty) return reject(diagnostic, FailurePhase::Argument, EINVAL);
    if (state_ == State::Unresolved) {
        diagnostic = receipt_->diagnostic.phase == FailurePhase::None
                         ? Diagnostic{FailurePhase::DescriptorClose, EIO}
                         : receipt_->diagnostic;
        return false;
    }

    // Establish the exact original majority before the first pathname
    // mutation. If KCMP is denied/unavailable or the documented one-slot
    // boundary is violated, neither the namespace nor any descriptor changes.
    if (state_ != State::Creating && !resolve_descriptor_custody(diagnostic)) return false;

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
        if (hooks_.before_final_remove != nullptr)
            hooks_.before_final_remove(directory_fd_,
                                       receipt_->original_basename.c_str(),
                                       current_basename_.c_str(),
                                       hooks_.context);
        // The boundary hook runs after the first validation.  Under this
        // lease's exclusive-namespace contract, this is the final possible
        // mutation boundary and this second validation is the unlink gate.
        if (!validate_named(current_basename_, false, named)) {
            transition(State::BindingLost);
            observe_residues();
            return reject(diagnostic, FailurePhase::Unlink, named.error_number);
        }
        if (unlinkat(directory_fd_, current_basename_.c_str(), 0) != 0)
            return reject(diagnostic, FailurePhase::Unlink, errno);
        receipt_->exact_unlinked = true;
        transition(State::Detached);
    }
    return finish_detached(diagnostic);
}

}  // namespace rut::test::fixture_exact_input_file_lease
