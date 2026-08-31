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
bool seed_ok(const char* seed) {
    return seed && std::strlen(seed) == 32 && std::strspn(seed, "0123456789abcdef") == 32;
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
    if (state_ == State::Owned || state_ == State::Quarantined) ok = settle(diagnostic);
    if (state_ != State::Removed) observe_residue();
    if (state_ != State::Removed) close_descriptors(diagnostic);
    const bool unresolved = state_ == State::PendingIdentity || state_ == State::BindingLost ||
                            state_ == State::RenamePendingValidation || state_ == State::Unresolved;
    if (!ok || unresolved) {
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
void PrivateDirectoryLease::transition(State state) {
    state_ = state;
    receipt_->state = state;
}
bool PrivateDirectoryLease::next_name(bool creation, std::string& name, Diagnostic& diagnostic) {
    const char* fixed = creation ? hooks_.creation_seed : nullptr;
    if (!creation && quarantine_index_ < hooks_.quarantine_seed_count)
        fixed = hooks_.quarantine_seeds[quarantine_index_++];
    std::array<char, 33> hex{};
    if (fixed)
        std::memcpy(hex.data(), fixed, 32);
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
                       (!hooks_.creation_seed || seed_ok(hooks_.creation_seed));
    for (std::size_t i = 0; seeds_valid && i != hooks_.quarantine_seed_count; ++i)
        seeds_valid = seed_ok(hooks_.quarantine_seeds[i]);
    if (!seeds_valid) return reject(diagnostic, FailurePhase::Argument, EINVAL);
    original_basename_.reserve(64);
    current_basename_.reserve(64);
    path_.reserve(80);
    receipt_->path.reserve(80);
    receipt_->original_basename.reserve(64);
    receipt_->last_candidate.reserve(64);
    parent_fd_ = open(kParent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat held_parent{}, named_parent{};
    if (parent_fd_ < 0 || fstat(parent_fd_, &held_parent) != 0 ||
        fstatat(AT_FDCWD, kParent, &named_parent, AT_SYMLINK_NOFOLLOW) != 0 ||
        held_parent.st_dev != named_parent.st_dev || held_parent.st_ino != named_parent.st_ino) {
        return reject(diagnostic, FailurePhase::Parent, errno ? errno : ESTALE);
    }
    for (unsigned attempt = 0; attempt != kAttempts; ++attempt) {
        if (!next_name(true, original_basename_, diagnostic)) return false;
        current_basename_ = original_basename_;
        path_ = std::string(kParent) + "/" + original_basename_;
        receipt_->path = path_;
        receipt_->original_basename = original_basename_;
        if (mkdirat(parent_fd_, original_basename_.c_str(), 0700) != 0) {
            if (errno == EEXIST && !hooks_.creation_seed) continue;
            return reject(diagnostic, FailurePhase::Create, errno);
        }
        transition(State::PendingIdentity);
        break;
    }
    if (state_ != State::PendingIdentity) return reject(diagnostic, FailurePhase::Create, EEXIST);
    if (hooks_.abort == AbortPoint::AfterMkdir) {
        transition(State::Unresolved);
        observe_residue();
        return reject(diagnostic, FailurePhase::Hook, ECANCELED);
    }
    directory_fd_ = openat(
        parent_fd_, original_basename_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat held{}, named{};
    if (directory_fd_ < 0 || fstat(directory_fd_, &held) != 0 ||
        fstatat(parent_fd_, original_basename_.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        held.st_dev != named.st_dev || held.st_ino != named.st_ino ||
        held.st_mode != named.st_mode || held.st_uid != named.st_uid ||
        held.st_gid != named.st_gid || !S_ISDIR(held.st_mode) || held.st_uid != getuid() ||
        held.st_gid != getgid()) {
        transition(State::Unresolved);
        observe_residue();
        return reject(diagnostic, FailurePhase::Identity, errno ? errno : ESTALE);
    }
    identity_ = identity_of(held);
    binding_prior_ = State::Owned;
    transition(State::Owned);
    if (hooks_.abort == AbortPoint::AfterFirstOwnedMatch)
        return reject(diagnostic, FailurePhase::Hook, ECANCELED);
    if (fchmod(directory_fd_, 0700) != 0 || fstat(directory_fd_, &held) != 0 ||
        fstatat(parent_fd_, original_basename_.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        held.st_dev != named.st_dev || held.st_ino != named.st_ino ||
        held.st_mode != named.st_mode || held.st_uid != named.st_uid ||
        held.st_gid != named.st_gid || (held.st_mode & 0777) != 0700 ||
        (named.st_mode & 0777) != 0700) {
        return reject(diagnostic, FailurePhase::Permission, errno ? errno : ESTALE);
    }
    identity_ = identity_of(held);
    return true;
}
bool PrivateDirectoryLease::validate_binding(Diagnostic& diagnostic) {
    struct stat held{}, named{};
    if (directory_fd_ >= 0 && parent_fd_ >= 0 && fstat(directory_fd_, &held) == 0 &&
        fstatat(parent_fd_, current_basename_.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_object(held, identity_) && same_object(named, identity_))
        return true;
    if (state_ != State::BindingLost) binding_prior_ = state_;
    transition(State::BindingLost);
    observe_residue();
    return reject(diagnostic, FailurePhase::Revalidate, errno ? errno : ESTALE);
}
bool PrivateDirectoryLease::revalidate(Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ != State::Owned && state_ != State::Quarantined && state_ != State::BindingLost)
        return reject(diagnostic, FailurePhase::Revalidate, EINVAL);
    const State restored = state_ == State::BindingLost ? binding_prior_ : state_;
    if (!validate_binding(diagnostic)) return false;
    transition(restored);
    receipt_->diagnostic = {};
    return true;
}
bool PrivateDirectoryLease::settle(Diagnostic& diagnostic) {
    diagnostic = {};
    receipt_->attempted = true;
    if (state_ == State::Removed) return true;
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
                renamed = true;
                break;
            }
            if (errno != EEXIST) return reject(diagnostic, FailurePhase::Quarantine, errno);
        }
        if (!renamed) return reject(diagnostic, FailurePhase::Quarantine, EEXIST);
        if (hooks_.after_quarantine_rename)
            hooks_.after_quarantine_rename(parent_fd_, current_basename_.c_str(), hooks_.context);
        struct stat held{}, named{};
        if (fstat(directory_fd_, &held) != 0 ||
            fstatat(parent_fd_, current_basename_.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_object(held, identity_) || !same_object(named, identity_)) {
            transition(State::Unresolved);
            observe_residue();
            return reject(diagnostic, FailurePhase::Quarantine, errno ? errno : ESTALE);
        }
        binding_prior_ = State::Quarantined;
        transition(State::Quarantined);
    }
    if (unlinkat(parent_fd_, current_basename_.c_str(), AT_REMOVEDIR) != 0) {
        observe_residue();
        return reject(diagnostic, FailurePhase::Remove, errno);
    }
    receipt_->object_removed = true;
    transition(State::Removed);
    observe_residue();
    close_descriptors(diagnostic);
    receipt_->diagnostic = diagnostic;
    return diagnostic.phase == FailurePhase::None;
}
void PrivateDirectoryLease::observe_residue() {
    if (parent_fd_ < 0 || current_basename_.empty()) {
        receipt_->residue = Residue::Unknown;
        return;
    }
    struct stat status{};
    if (fstatat(parent_fd_, current_basename_.c_str(), &status, AT_SYMLINK_NOFOLLOW) == 0)
        receipt_->residue = Residue::Present;
    else
        receipt_->residue = errno == ENOENT ? Residue::Absent : Residue::Unknown;
}
void PrivateDirectoryLease::close_descriptors(Diagnostic& diagnostic) {
    bool ok = true;
    for (int* slot : {&directory_fd_, &parent_fd_}) {
        if (*slot < 0) continue;
        const int descriptor = *slot;
        *slot = -1;
        if (close(descriptor) != 0) {
            ok = false;
            diagnostic = {FailurePhase::Close, errno};
        }
    }
    receipt_->descriptor_closed = ok;
}
}  // namespace rut::test::fixture_private_directory_lease
