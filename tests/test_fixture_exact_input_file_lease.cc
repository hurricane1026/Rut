#include "fixture_exact_input_file_lease.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace input = rut::test::fixture_exact_input_file_lease;
namespace directory = rut::test::fixture_private_directory_lease;
namespace {
constexpr char kBytes[] = "server { listen 192.0.2.10:8080; }\n";

bool check(bool value, const char* message) {
    if (!value) std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
    return value;
}
std::string seed(unsigned tag) {
    std::array<char, 33> value{};
    std::snprintf(value.data(), value.size(), "%032x", getpid() * 128u + tag);
    return value.data();
}
directory::HooksForTesting directory_hooks(unsigned tag) {
    return {.creation_seed = seed(tag)};
}
input::HooksForTesting input_hooks(unsigned tag) {
    return {.creation_seed = seed(tag), .quarantine_seed = seed(tag + 1u)};
}
bool make_directory(unsigned tag,
                    directory::PrivateDirectoryLease& lease,
                    directory::Diagnostic& diagnostic) {
    return directory::PrivateDirectoryLease::create_with_hooks_for_testing(
        directory_hooks(tag), lease, diagnostic);
}
bool create(unsigned tag,
            directory::PrivateDirectoryLease& owner,
            input::ExactInputFileLease& lease,
            input::Diagnostic& diagnostic) {
    return input::ExactInputFileLease::create_with_hooks_for_testing(
        owner, kBytes, sizeof(kBytes) - 1u, input_hooks(tag), lease, diagnostic);
}
bool failed(const input::Diagnostic& diagnostic, input::FailurePhase phase) {
    return diagnostic.phase == phase && diagnostic.error_number != 0;
}
bool same_inode(const struct stat& left, const struct stat& right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino;
}
bool stat_at(int parent, const std::string& name, struct stat& value) {
    return fstatat(parent, name.c_str(), &value, AT_SYMLINK_NOFOLLOW) == 0;
}
bool write_file(int parent, const std::string& name, const std::string& bytes) {
    const int fd =
        openat(parent, name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    std::size_t offset = 0u;
    while (offset != bytes.size()) {
        const ssize_t count = write(fd, bytes.data() + offset, bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return close(fd), false;
        offset += static_cast<std::size_t>(count);
    }
    return fsync(fd) == 0 && close(fd) == 0;
}
bool rewrite(int parent, const std::string& name, const std::string& bytes) {
    const int fd = openat(parent, name.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    std::size_t offset = 0u;
    while (offset != bytes.size()) {
        const ssize_t count =
            pwrite(fd, bytes.data() + offset, bytes.size() - offset, static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return close(fd), false;
        offset += static_cast<std::size_t>(count);
    }
    return ftruncate(fd, static_cast<off_t>(bytes.size())) == 0 && fsync(fd) == 0 && close(fd) == 0;
}
bool directory_empty(int fd) {
    const int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0) return false;
    DIR* stream = fdopendir(duplicate);
    if (stream == nullptr) return close(duplicate), false;
    bool empty = true;
    errno = 0;
    while (dirent* entry = readdir(stream)) {
        if (std::strcmp(entry->d_name, ".") != 0 && std::strcmp(entry->d_name, "..") != 0) {
            empty = false;
            break;
        }
        errno = 0;
    }
    const int error = errno;
    return closedir(stream) == 0 && error == 0 && empty;
}
bool fd_snapshot(std::vector<int>& values) {
    values.clear();
    DIR* stream = opendir("/proc/self/fd");
    if (stream == nullptr) return false;
    const int own = dirfd(stream);
    errno = 0;
    while (dirent* entry = readdir(stream)) {
        int fd = -1;
        if (std::sscanf(entry->d_name, "%d", &fd) == 1 && fd != own) values.push_back(fd);
        errno = 0;
    }
    const int error = errno;
    const bool closed = closedir(stream) == 0;
    std::sort(values.begin(), values.end());
    return closed && error == 0;
}
bool complete(const std::shared_ptr<const input::CleanupReceipt>& receipt) {
    return receipt && receipt->attempted && receipt->semantic_validated &&
           receipt->path_quarantined && receipt->exact_unlinked && receipt->detached_inode_proven &&
           receipt->descriptor_closed && receipt->directory_settled &&
           receipt->settlement_complete && receipt->state == input::State::Settled &&
           receipt->quarantine_residue == input::Residue::Absent;
}

bool invalid_argument_tests() {
    directory::PrivateDirectoryLease owner;
    directory::Diagnostic directory_diagnostic;
    if (!make_directory(1u, owner, directory_diagnostic)) return false;
    input::Diagnostic diagnostic;
    input::ExactInputFileLease null_lease, empty_lease, overflow_lease, maximum_lease;
    std::array<char, input::kMaximumInputBytes + 1u> overflow{};
    overflow.fill('z');
    const bool rejected =
        !input::ExactInputFileLease::create(owner, nullptr, 1u, null_lease, diagnostic) &&
        failed(diagnostic, input::FailurePhase::Argument) &&
        !input::ExactInputFileLease::create(owner, kBytes, 0u, empty_lease, diagnostic) &&
        failed(diagnostic, input::FailurePhase::Argument) &&
        !input::ExactInputFileLease::create(
            owner, overflow.data(), overflow.size(), overflow_lease, diagnostic) &&
        failed(diagnostic, input::FailurePhase::Argument) && directory_empty(owner.descriptor()) &&
        input::ExactInputFileLease::create(
            owner, overflow.data(), input::kMaximumInputBytes, maximum_lease, diagnostic) &&
        maximum_lease.revalidate(diagnostic) && maximum_lease.cleanup(diagnostic);
    return check(rejected && owner.settle(directory_diagnostic),
                 "null/empty/overflow mutated the directory");
}

bool normal_lifecycle_and_ordering_test() {
    std::vector<int> before, after;
    if (!fd_snapshot(before)) return false;
    std::shared_ptr<const input::CleanupReceipt> receipt, destructor_receipt;
    bool ok = false;
    {
        directory::PrivateDirectoryLease owner;
        directory::Diagnostic directory_diagnostic;
        input::ExactInputFileLease lease;
        input::Diagnostic diagnostic;
        if (!make_directory(4u, owner, directory_diagnostic) ||
            !create(5u, owner, lease, diagnostic))
            return false;
        receipt = lease.cleanup_receipt();
        struct stat held{}, named{};
        const int fd_flags = fcntl(lease.descriptor(), F_GETFD);
        const int status_flags = fcntl(lease.descriptor(), F_GETFL);
        errno = 0;
        const bool ordering =
            unlinkat(AT_FDCWD, owner.path().c_str(), AT_REMOVEDIR) != 0 && errno == ENOTEMPTY;
        ok = ordering && fstat(lease.descriptor(), &held) == 0 &&
             stat_at(owner.descriptor(), lease.basename(), named) && same_inode(held, named) &&
             (held.st_mode & 0777) == 0600 && held.st_uid == getuid() && held.st_gid == getgid() &&
             held.st_nlink == 1u && held.st_size == static_cast<off_t>(sizeof(kBytes) - 1u) &&
             (fd_flags & FD_CLOEXEC) != 0 && (status_flags & O_ACCMODE) == O_RDONLY &&
             lease.revalidate(diagnostic) && lease.revalidate(diagnostic) &&
             lease.cleanup(diagnostic) && lease.cleanup(diagnostic) && complete(receipt);
        {
            input::ExactInputFileLease destructor_lease;
            ok = ok && create(7u, owner, destructor_lease, diagnostic);
            destructor_receipt = destructor_lease.cleanup_receipt();
        }
        ok = ok && complete(destructor_receipt) && owner.settle(directory_diagnostic);
    }
    return check(ok && fd_snapshot(after) && before == after,
                 "normal lifecycle, ordering, receipt, or FD baseline failed");
}

input::FailurePhase phase_for(input::CreationFaultForTesting fault) {
    switch (fault) {
        case input::CreationFaultForTesting::PreOpen:
            return input::FailurePhase::Hook;
        case input::CreationFaultForTesting::Open:
            return input::FailurePhase::Open;
        case input::CreationFaultForTesting::WritePartial:
        case input::CreationFaultForTesting::WriteError:
            return input::FailurePhase::Write;
        case input::CreationFaultForTesting::Sync:
            return input::FailurePhase::Sync;
        case input::CreationFaultForTesting::Reopen:
            return input::FailurePhase::Reopen;
        case input::CreationFaultForTesting::Verification:
            return input::FailurePhase::Verification;
        case input::CreationFaultForTesting::WriterCloseUncertain:
            return input::FailurePhase::WriterClose;
        case input::CreationFaultForTesting::None:
            break;
    }
    return input::FailurePhase::None;
}
bool creation_failure_tests() {
    constexpr std::array faults = {input::CreationFaultForTesting::PreOpen,
                                   input::CreationFaultForTesting::Open,
                                   input::CreationFaultForTesting::WritePartial,
                                   input::CreationFaultForTesting::WriteError,
                                   input::CreationFaultForTesting::Sync,
                                   input::CreationFaultForTesting::Reopen,
                                   input::CreationFaultForTesting::Verification,
                                   input::CreationFaultForTesting::WriterCloseUncertain};
    unsigned tag = 10u;
    for (const auto fault : faults) {
        directory::PrivateDirectoryLease owner;
        directory::Diagnostic directory_diagnostic;
        input::ExactInputFileLease lease;
        input::Diagnostic diagnostic;
        if (!make_directory(tag++, owner, directory_diagnostic)) return false;
        auto hooks = input_hooks(tag);
        tag += 2u;
        hooks.creation_fault = fault;
        const bool refused = !input::ExactInputFileLease::create_with_hooks_for_testing(
                                 owner, kBytes, sizeof(kBytes) - 1u, hooks, lease, diagnostic) &&
                             failed(diagnostic, phase_for(fault)) &&
                             failed(lease.cleanup_receipt()->diagnostic, phase_for(fault)) &&
                             directory_empty(owner.descriptor()) &&
                             owner.settle(directory_diagnostic);
        if (!check(refused, "creation fault was not causal or left residue")) return false;
    }
    return true;
}

bool byte_metadata_mutation_tests() {
    directory::PrivateDirectoryLease owner;
    directory::Diagnostic directory_diagnostic;
    input::ExactInputFileLease lease;
    input::Diagnostic diagnostic;
    if (!make_directory(40u, owner, directory_diagnostic) || !create(41u, owner, lease, diagnostic))
        return false;
    const std::string original(kBytes, sizeof(kBytes) - 1u);
    std::string changed = original;
    changed.front() = 'x';
    const int parent = owner.descriptor();
    const std::string name = lease.basename();
    bool ok = rewrite(parent, name, changed) && !lease.revalidate(diagnostic) &&
              failed(diagnostic, input::FailurePhase::Bytes) && rewrite(parent, name, original) &&
              lease.revalidate(diagnostic);
    const int writer = openat(parent, name.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    ok = ok && writer >= 0 && ftruncate(writer, static_cast<off_t>(original.size() + 1u)) == 0 &&
         close(writer) == 0 && !lease.revalidate(diagnostic) &&
         failed(diagnostic, input::FailurePhase::Revalidate) && rewrite(parent, name, original) &&
         lease.revalidate(diagnostic);
    ok = ok && fchmodat(parent, name.c_str(), 0640, 0) == 0 && !lease.revalidate(diagnostic) &&
         fchmodat(parent, name.c_str(), 0600, 0) == 0 && lease.revalidate(diagnostic) &&
         linkat(parent, name.c_str(), parent, "extra-link", 0) == 0 &&
         !lease.revalidate(diagnostic) && unlinkat(parent, "extra-link", 0) == 0 &&
         lease.revalidate(diagnostic) && lease.cleanup(diagnostic) &&
         owner.settle(directory_diagnostic);
    return check(ok, "byte/size/mode/nlink mutation was accepted or not recoverable");
}

enum class ReplacementKind { Regular, Symlink, Fifo };
bool replacement_test(ReplacementKind kind, unsigned tag) {
    directory::PrivateDirectoryLease owner;
    directory::Diagnostic directory_diagnostic;
    input::ExactInputFileLease lease;
    input::Diagnostic diagnostic;
    if (!make_directory(tag, owner, directory_diagnostic) ||
        !create(tag + 1u, owner, lease, diagnostic))
        return false;
    const int parent = owner.descriptor();
    const std::string name = lease.basename();
    const std::string saved = name + ".owned";
    bool prepared = renameat(parent, name.c_str(), parent, saved.c_str()) == 0;
    if (kind == ReplacementKind::Regular)
        prepared = prepared && write_file(parent, name, "foreign");
    else if (kind == ReplacementKind::Symlink)
        prepared = prepared && symlinkat("foreign-target", parent, name.c_str()) == 0;
    else
        prepared = prepared && mkfifoat(parent, name.c_str(), 0600) == 0;
    struct stat before{}, after{};
    const bool refused = prepared && stat_at(parent, name, before) &&
                         !lease.revalidate(diagnostic) && !lease.cleanup(diagnostic) &&
                         stat_at(parent, name, after) && before.st_dev == after.st_dev &&
                         before.st_ino == after.st_ino && before.st_mode == after.st_mode;
    const bool restored = refused && unlinkat(parent, name.c_str(), 0) == 0 &&
                          renameat(parent, saved.c_str(), parent, name.c_str()) == 0 &&
                          lease.revalidate(diagnostic) && lease.cleanup(diagnostic) &&
                          owner.settle(directory_diagnostic);
    return check(restored, "regular/symlink/FIFO replacement was touched or not recoverable");
}

bool descriptor_mutation_tests() {
    directory::PrivateDirectoryLease owner;
    directory::Diagnostic directory_diagnostic;
    input::ExactInputFileLease lease;
    input::Diagnostic diagnostic;
    if (!make_directory(55u, owner, directory_diagnostic) || !create(56u, owner, lease, diagnostic))
        return false;
    const int leased = lease.descriptor();
    const int flags = fcntl(leased, F_GETFD);
    bool ok = flags >= 0 && fcntl(leased, F_SETFD, flags & ~FD_CLOEXEC) == 0 &&
              !lease.revalidate(diagnostic) && fcntl(leased, F_SETFD, flags | FD_CLOEXEC) == 0 &&
              lease.revalidate(diagnostic);
    const int access_saved = fcntl(leased, F_DUPFD_CLOEXEC, 3);
    const int wrong_access =
        openat(owner.descriptor(), lease.basename().c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    ok = ok && access_saved >= 0 && wrong_access >= 0 && dup2(wrong_access, leased) == leased &&
         fcntl(leased, F_SETFD, FD_CLOEXEC) == 0 && !lease.revalidate(diagnostic) &&
         dup2(access_saved, leased) == leased && fcntl(leased, F_SETFD, FD_CLOEXEC) == 0 &&
         close(access_saved) == 0 && close(wrong_access) == 0 && lease.revalidate(diagnostic);
    const int saved = fcntl(leased, F_DUPFD_CLOEXEC, 3);
    const int foreign = open("/dev/null", O_WRONLY | O_CLOEXEC);
    ok = ok && saved >= 0 && foreign >= 0 && dup2(foreign, leased) == leased &&
         !lease.revalidate(diagnostic) && !lease.cleanup(diagnostic) &&
         fcntl(foreign, F_GETFD) >= 0 && dup2(saved, leased) == leased &&
         fcntl(leased, F_SETFD, FD_CLOEXEC) == 0 && close(saved) == 0 &&
         lease.cleanup(diagnostic) && close(foreign) == 0 && owner.settle(directory_diagnostic);
    return check(ok, "descriptor flags/replacement was accepted or foreign FD was closed");
}

input::FailurePhase cleanup_phase(input::CleanupFaultForTesting fault) {
    switch (fault) {
        case input::CleanupFaultForTesting::QuarantineRename:
            return input::FailurePhase::Quarantine;
        case input::CleanupFaultForTesting::Unlink:
            return input::FailurePhase::Unlink;
        case input::CleanupFaultForTesting::DirectorySync:
            return input::FailurePhase::DirectorySettlement;
        case input::CleanupFaultForTesting::ReaderCloseUncertain:
            return input::FailurePhase::DescriptorClose;
        case input::CleanupFaultForTesting::None:
            break;
    }
    return input::FailurePhase::None;
}
bool cleanup_fault_tests() {
    constexpr std::array faults = {input::CleanupFaultForTesting::QuarantineRename,
                                   input::CleanupFaultForTesting::Unlink,
                                   input::CleanupFaultForTesting::DirectorySync,
                                   input::CleanupFaultForTesting::ReaderCloseUncertain};
    unsigned tag = 60u;
    for (const auto fault : faults) {
        directory::PrivateDirectoryLease owner;
        directory::Diagnostic directory_diagnostic;
        input::ExactInputFileLease lease;
        input::Diagnostic diagnostic;
        if (!make_directory(tag++, owner, directory_diagnostic)) return false;
        auto hooks = input_hooks(tag);
        tag += 2u;
        hooks.cleanup_fault = fault;
        if (!input::ExactInputFileLease::create_with_hooks_for_testing(
                owner, kBytes, sizeof(kBytes) - 1u, hooks, lease, diagnostic))
            return false;
        const auto receipt = lease.cleanup_receipt();
        const bool retried =
            !lease.cleanup(diagnostic) && failed(diagnostic, cleanup_phase(fault)) &&
            failed(receipt->diagnostic, cleanup_phase(fault)) && lease.cleanup(diagnostic) &&
            receipt->settlement_complete && failed(receipt->diagnostic, cleanup_phase(fault)) &&
            owner.settle(directory_diagnostic);
        if (!check(retried, "cleanup fault did not preserve cause and retry to zero residue"))
            return false;
    }
    return true;
}

struct ExchangeMutation {
    std::string foreign_name;
    std::string quarantine;
    bool exchanged = false;
};
void exchange_after_rename(int directory_fd, const char*, const char* quarantine, void* opaque) {
    auto& mutation = *static_cast<ExchangeMutation*>(opaque);
    mutation.quarantine = quarantine;
#ifdef SYS_renameat2
    mutation.exchanged = syscall(SYS_renameat2,
                                 directory_fd,
                                 mutation.foreign_name.c_str(),
                                 directory_fd,
                                 quarantine,
                                 RENAME_EXCHANGE) == 0;
#endif
}
bool quarantine_exchange_test() {
#ifndef SYS_renameat2
    return true;
#else
    directory::PrivateDirectoryLease owner;
    directory::Diagnostic directory_diagnostic;
    input::ExactInputFileLease lease;
    input::Diagnostic diagnostic;
    if (!make_directory(80u, owner, directory_diagnostic)) return false;
    ExchangeMutation mutation{.foreign_name = "foreign-exchange", .quarantine = {}};
    if (!write_file(owner.descriptor(), mutation.foreign_name, "foreign")) return false;
    auto hooks = input_hooks(81u);
    hooks.after_quarantine_rename = exchange_after_rename;
    hooks.context = &mutation;
    if (!input::ExactInputFileLease::create_with_hooks_for_testing(
            owner, kBytes, sizeof(kBytes) - 1u, hooks, lease, diagnostic))
        return false;
    const std::string original = lease.basename();
    struct stat foreign_before{}, foreign_after{};
    const bool refused = stat_at(owner.descriptor(), mutation.foreign_name, foreign_before) &&
                         !lease.cleanup(diagnostic) && mutation.exchanged &&
                         failed(diagnostic, input::FailurePhase::Quarantine) &&
                         stat_at(owner.descriptor(), mutation.quarantine, foreign_after) &&
                         same_inode(foreign_before, foreign_after);
    const std::string foreign_saved = "foreign-survived";
    const bool restored = refused &&
                          renameat(owner.descriptor(),
                                   mutation.quarantine.c_str(),
                                   owner.descriptor(),
                                   foreign_saved.c_str()) == 0 &&
                          renameat(owner.descriptor(),
                                   mutation.foreign_name.c_str(),
                                   owner.descriptor(),
                                   original.c_str()) == 0 &&
                          lease.revalidate(diagnostic) && lease.cleanup(diagnostic) &&
                          stat_at(owner.descriptor(), foreign_saved, foreign_after) &&
                          same_inode(foreign_before, foreign_after) &&
                          unlinkat(owner.descriptor(), foreign_saved.c_str(), 0) == 0 &&
                          owner.settle(directory_diagnostic);
    return check(restored, "quarantine exchange touched foreign inode or prevented safe recovery");
#endif
}
}  // namespace

int main() {
    if (!invalid_argument_tests() || !normal_lifecycle_and_ordering_test() ||
        !creation_failure_tests() || !byte_metadata_mutation_tests() ||
        !replacement_test(ReplacementKind::Regular, 45u) ||
        !replacement_test(ReplacementKind::Symlink, 48u) ||
        !replacement_test(ReplacementKind::Fifo, 51u) || !descriptor_mutation_tests() ||
        !cleanup_fault_tests() || !quarantine_exchange_test())
        return 1;
    std::puts("PASS: #358 exact input file lease");
}
