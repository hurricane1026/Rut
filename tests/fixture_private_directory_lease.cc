#include "fixture_private_directory_lease.h"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace rut::test::fixture_private_directory_lease {
namespace {
constexpr unsigned kAttempts = 32;
constexpr char kParent[] = "/tmp";
Identity identity_of(const struct stat& value) {
    using U = std::uint64_t;
    return {U(value.st_dev), U(value.st_ino), U(value.st_mode), U(value.st_uid), U(value.st_gid)};
}
bool same_object(const struct stat& value, const Identity& expected) {
    return S_ISDIR(value.st_mode) && static_cast<std::uint64_t>(value.st_dev) == expected.device &&
           static_cast<std::uint64_t>(value.st_ino) == expected.inode &&
           static_cast<std::uint64_t>(value.st_uid) == expected.uid &&
           static_cast<std::uint64_t>(value.st_gid) == expected.gid;
}
bool same_private(const struct stat& value, const Identity& expected) {
    return same_object(value, expected) &&
           static_cast<std::uint64_t>(value.st_mode) == expected.mode &&
           (value.st_mode & 0777) == 0700;
}
bool same_metadata(const struct stat& left, const struct stat& right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_mode == right.st_mode && left.st_uid == right.st_uid &&
           left.st_gid == right.st_gid;
}
bool read_pair(int held_fd,
               int parent_fd,
               const std::string& name,
               struct stat& held,
               struct stat& named,
               int& error) {
    if (fstat(held_fd, &held) != 0 ||
        fstatat(parent_fd, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
        error = errno;
        return false;
    }
    return true;
}
bool seed_ok(const std::string& seed) {
    return seed.size() == 32 && std::strspn(seed.c_str(), "0123456789abcdef") == 32;
}
Residue observe_name(int parent, const std::string& name) {
    if (parent < 0 || name.empty()) return Residue::Unknown;
    struct stat status{};
    if (fstatat(parent, name.c_str(), &status, AT_SYMLINK_NOFOLLOW) == 0) return Residue::Present;
    return errno == ENOENT ? Residue::Absent : Residue::Unknown;
}
int rename_noreplace(int fd, const char* from, const char* to) {
#ifdef SYS_renameat2
    return static_cast<int>(syscall(SYS_renameat2, fd, from, fd, to, RENAME_NOREPLACE));
#else
    (void)fd;
    (void)from;
    (void)to;
    errno = ENOSYS;
    return -1;
#endif
}
}  // namespace

PrivateDirectoryLease::PrivateDirectoryLease() : receipt_(std::make_shared<SettlementReceipt>()) {}
PrivateDirectoryLease::~PrivateDirectoryLease() {
    Diagnostic diagnostic;
    bool ok = true;
    const bool settling =
        state_ == State::Owned || state_ == State::Quarantined || state_ == State::Removed;
    if (settling) ok = settle(diagnostic);
    if (!settling && state_ != State::Empty) receipt_->attempted = true;
    if (!receipt_->settlement_complete) {
        observe_residues();
        close_descriptors(diagnostic);
    }
    const bool unresolved = state_ == State::PendingIdentity || state_ == State::BindingLost ||
                            state_ == State::RenamePendingValidation || state_ == State::Unresolved;
    if (!ok || unresolved || (state_ == State::Removed && !receipt_->settlement_complete)) {
        if (diagnostic.phase != FailurePhase::None) receipt_->diagnostic = diagnostic;
        std::fprintf(stderr,
                     "FAIL [#377 dir]: state=%u phase=%u errno=%d\n",
                     static_cast<unsigned>(state_),
                     static_cast<unsigned>(receipt_->diagnostic.phase),
                     receipt_->diagnostic.error_number);
    }
}
bool PrivateDirectoryLease::create(PrivateDirectoryLease& lease, Diagnostic& diagnostic) {
    return lease.create_impl(nullptr, diagnostic);
}
bool PrivateDirectoryLease::create_with_hooks_for_testing(const HooksForTesting& hooks,
                                                          PrivateDirectoryLease& lease,
                                                          Diagnostic& diagnostic) {
    return lease.create_impl(&hooks, diagnostic);
}
bool PrivateDirectoryLease::reject(Diagnostic& diagnostic, FailurePhase phase, int error_number) {
    diagnostic = {phase, error_number};
    receipt_->diagnostic = diagnostic;
    return false;
}
bool PrivateDirectoryLease::abandon(Diagnostic& diagnostic, FailurePhase phase, int error_number) {
    transition(State::Unresolved);
    receipt_->current_basename_known = false;
    observe_residues();
    return reject(diagnostic, phase, error_number);
}
void PrivateDirectoryLease::transition(State state) {
    state_ = state;
    receipt_->state = state;
}
bool PrivateDirectoryLease::next_name(bool creation, std::string& name, Diagnostic& diagnostic) {
    const std::string* fixed =
        creation && !hooks_.creation_seed.empty() ? &hooks_.creation_seed : nullptr;
    if (!creation && quarantine_index_ < hooks_.quarantine_seed_count)
        fixed = &hooks_.quarantine_seeds[quarantine_index_++];
    std::array<char, 33> hex{};
    if (fixed)
        std::memcpy(hex.data(), fixed->data(), 32);
    else {
        std::array<unsigned char, 16> random{};
        std::size_t offset = 0;
        for (unsigned call = 0; call != kAttempts && offset != random.size(); ++call) {
            const ssize_t count =
                getrandom(random.data() + offset, random.size() - offset, GRND_NONBLOCK);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0)
                return reject(diagnostic, FailurePhase::Random, count < 0 ? errno : EIO);
            offset += static_cast<std::size_t>(count);
        }
        if (offset != random.size()) return reject(diagnostic, FailurePhase::Random, EAGAIN);
        constexpr char digits[] = "0123456789abcdef";
        for (std::size_t i = 0; i != random.size(); ++i) {
            hex[i * 2] = digits[random[i] >> 4];
            hex[i * 2 + 1] = digits[random[i] & 15];
        }
    }
    name.assign(creation ? "rut377-private-" : ".rut377-directory-quarantine-");
    name.append(hex.data(), 32);
    return true;
}
bool PrivateDirectoryLease::create_impl(const HooksForTesting* hooks, Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ != State::Empty || parent_fd_ >= 0 || directory_fd_ >= 0 || !receipt_)
        return reject(diagnostic, FailurePhase::Argument, EINVAL);
    hooks_ = hooks ? *hooks : HooksForTesting{};
    bool seeds_valid = hooks_.quarantine_seed_count <= hooks_.quarantine_seeds.size() &&
                       (hooks_.creation_seed.empty() || seed_ok(hooks_.creation_seed));
    for (std::size_t i = 0; seeds_valid && i != hooks_.quarantine_seed_count; ++i)
        seeds_valid = seed_ok(hooks_.quarantine_seeds[i]);
    if (!seeds_valid) return reject(diagnostic, FailurePhase::Argument, EINVAL);
    current_basename_.reserve(64);
    receipt_->path.reserve(80);
    receipt_->original_basename.reserve(64);
    receipt_->last_candidate.reserve(64);
    parent_fd_ = open(kParent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat held_parent{}, named_parent{};
    if (parent_fd_ < 0) return reject(diagnostic, FailurePhase::Parent, errno);
    int parent_error = 0;
    if (!read_pair(parent_fd_, AT_FDCWD, kParent, held_parent, named_parent, parent_error) ||
        held_parent.st_dev != named_parent.st_dev || held_parent.st_ino != named_parent.st_ino)
        return reject(diagnostic, FailurePhase::Parent, parent_error == 0 ? ESTALE : parent_error);
    for (unsigned attempt = 0; attempt != kAttempts; ++attempt) {
        if (!next_name(true, receipt_->original_basename, diagnostic)) return false;
        current_basename_ = receipt_->original_basename;
        receipt_->path = std::string(kParent) + "/" + receipt_->original_basename;
        if (mkdirat(parent_fd_, receipt_->original_basename.c_str(), 0700) != 0) {
            if (errno == EEXIST && hooks_.creation_seed.empty()) continue;
            return reject(diagnostic, FailurePhase::Create, errno);
        }
        transition(State::PendingIdentity);
        break;
    }
    if (state_ != State::PendingIdentity) return reject(diagnostic, FailurePhase::Create, EEXIST);
    if (hooks_.abort == AbortPoint::AfterMkdir)
        return abandon(diagnostic, FailurePhase::Hook, ECANCELED);
    directory_fd_ = openat(parent_fd_,
                           receipt_->original_basename.c_str(),
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat held{}, named{};
    int identity_error = 0;
    if (directory_fd_ < 0 ||
        !read_pair(
            directory_fd_, parent_fd_, receipt_->original_basename, held, named, identity_error) ||
        !same_metadata(held, named) || !S_ISDIR(held.st_mode) || held.st_uid != getuid() ||
        held.st_gid != getgid()) {
        if (directory_fd_ < 0) identity_error = errno;
        if (identity_error == 0) identity_error = ESTALE;
        return abandon(diagnostic, FailurePhase::Identity, identity_error);
    }
    identity_ = identity_of(held);
    binding_prior_ = State::Owned;
    transition(State::Owned);
    receipt_->current_basename_known = true;
    if (hooks_.abort == AbortPoint::AfterFirstOwnedMatch)
        return reject(diagnostic, FailurePhase::Hook, ECANCELED);
    if (fchmod(directory_fd_, 0700) != 0)
        return reject(diagnostic, FailurePhase::Permission, errno);
    identity_.mode = (identity_.mode & ~std::uint64_t{0777}) | 0700;
    identity_error = 0;
    if (!read_pair(
            directory_fd_, parent_fd_, receipt_->original_basename, held, named, identity_error)) {
        return reject(
            diagnostic, FailurePhase::Permission, identity_error == 0 ? ESTALE : identity_error);
    }
    if (!same_metadata(held, named) || (held.st_mode & 0777) != 0700)
        return reject(diagnostic, FailurePhase::Permission, ESTALE);
    identity_ = identity_of(held);
    return true;
}
bool PrivateDirectoryLease::validate_binding(Diagnostic& diagnostic) {
    struct stat held{}, named{};
    int error = 0;
    const bool read = directory_fd_ >= 0 && parent_fd_ >= 0 &&
                      read_pair(directory_fd_, parent_fd_, current_basename_, held, named, error);
    if (read && same_private(held, identity_) && same_private(named, identity_)) return true;
    if (!read && error == 0) error = EBADF;
    if (read) error = ESTALE;
    if (state_ != State::BindingLost) binding_prior_ = state_;
    transition(State::BindingLost);
    receipt_->current_basename_known = false;
    observe_residues();
    return reject(diagnostic, FailurePhase::Revalidate, error);
}
bool PrivateDirectoryLease::revalidate(Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ != State::Owned && state_ != State::Quarantined && state_ != State::BindingLost)
        return reject(diagnostic, FailurePhase::Revalidate, EINVAL);
    const State restored = state_ == State::BindingLost ? binding_prior_ : state_;
    if (!validate_binding(diagnostic)) return false;
    transition(restored);
    receipt_->current_basename_known = true;
    receipt_->diagnostic = {};
    return true;
}
bool PrivateDirectoryLease::settle(Diagnostic& diagnostic) {
    diagnostic = {};
    receipt_->attempted = true;
    if (state_ == State::Removed) return finalize_removed(diagnostic);
    if (!revalidate(diagnostic)) return false;
    if (state_ == State::Owned) {
        std::string candidate;
        candidate.reserve(64);
        bool renamed = false;
        for (unsigned attempt = 0; attempt != kAttempts; ++attempt) {
            if (!next_name(false, candidate, diagnostic)) return false;
            receipt_->last_candidate = candidate;
            if (rename_noreplace(parent_fd_, current_basename_.c_str(), candidate.c_str()) == 0) {
                transition(State::RenamePendingValidation);
                current_basename_ = candidate;
                receipt_->current_basename_known = false;
                renamed = true;
                break;
            }
            if (errno != EEXIST) return reject(diagnostic, FailurePhase::Quarantine, errno);
        }
        if (!renamed) return reject(diagnostic, FailurePhase::Quarantine, EEXIST);
        if (hooks_.after_quarantine_rename)
            hooks_.after_quarantine_rename(parent_fd_, current_basename_.c_str(), hooks_.context);
        struct stat held{}, named{};
        int error = 0;
        const bool read =
            read_pair(directory_fd_, parent_fd_, current_basename_, held, named, error);
        if (!read || !same_private(held, identity_) || !same_private(named, identity_)) {
            if (read) error = ESTALE;
            return abandon(diagnostic, FailurePhase::Quarantine, error);
        }
        binding_prior_ = State::Quarantined;
        transition(State::Quarantined);
        receipt_->current_basename_known = true;
    }
    if (unlinkat(parent_fd_, current_basename_.c_str(), AT_REMOVEDIR) != 0) {
        const int error = errno;
        observe_residues();
        return reject(diagnostic, FailurePhase::Remove, error);
    }
    receipt_->object_removed = true;
    receipt_->current_basename_known = false;
    transition(State::Removed);
    return finalize_removed(diagnostic);
}
bool PrivateDirectoryLease::finalize_removed(Diagnostic& diagnostic) {
    if (receipt_->settlement_complete) return true;
    observe_residues();
    if (directory_fd_ >= 0) {
        const int descriptor = directory_fd_;
        directory_fd_ = -1;
        if (close(descriptor) != 0) {
            close_failed_ = true;
            return reject(diagnostic, FailurePhase::Close, errno);
        }
    }
    if (parent_fd_ < 0 || close_failed_) return receipt_->settlement_complete;
    if (fsync(parent_fd_) != 0) return reject(diagnostic, FailurePhase::Sync, errno);
    receipt_->namespace_synced = true;
    if (receipt_->original_residue != Residue::Absent ||
        receipt_->candidate_residue != Residue::Absent)
        return reject(diagnostic,
                      FailurePhase::Revalidate,
                      receipt_->original_residue == Residue::Present ||
                              receipt_->candidate_residue == Residue::Present
                          ? EEXIST
                          : ESTALE);
    close_descriptors(diagnostic);
    receipt_->settlement_complete = receipt_->descriptor_closed && !close_failed_;
    if (receipt_->settlement_complete) receipt_->diagnostic = diagnostic = {};
    return receipt_->settlement_complete;
}
void PrivateDirectoryLease::observe_residues() {
    const int saved = errno;
    receipt_->original_residue = observe_name(parent_fd_, receipt_->original_basename);
    receipt_->candidate_residue = observe_name(parent_fd_, receipt_->last_candidate);
    errno = saved;
}
void PrivateDirectoryLease::close_descriptors(Diagnostic& diagnostic) {
    bool ok = true;
    for (int* slot : {&directory_fd_, &parent_fd_}) {
        if (*slot < 0) continue;
        const int descriptor = *slot;
        *slot = -1;
        if (close(descriptor) != 0) {
            ok = false;
            close_failed_ = true;
            diagnostic = {FailurePhase::Close, errno};
        }
    }
    receipt_->descriptor_closed = ok && !close_failed_;
    if (!ok) receipt_->diagnostic = diagnostic;
}
}  // namespace rut::test::fixture_private_directory_lease
