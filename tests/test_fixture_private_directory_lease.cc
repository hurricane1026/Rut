#include "fixture_private_directory_lease.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
namespace directory = rut::test::fixture_private_directory_lease;
namespace {
bool check(bool value, const char* message) {
    if (!value) std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
    return value;
}
std::string seed(unsigned tag) {
    std::array<char, 33> bytes{};
    std::snprintf(bytes.data(), bytes.size(), "%032x", getpid() * 16u + tag);
    return bytes.data();
}
bool identity_at(int parent, const std::string& name, directory::Identity& identity) {
    struct stat status{};
    if (fstatat(parent, name.c_str(), &status, AT_SYMLINK_NOFOLLOW) != 0) return false;
    identity = {std::uint64_t(status.st_dev), std::uint64_t(status.st_ino)};
    return true;
}
bool same(const directory::Identity& left, const directory::Identity& right) {
    return left.device == right.device && left.inode == right.inode;
}
bool absent_at(int parent, const std::string& name) {
    directory::Identity unused;
    return !identity_at(parent, name, unused) && errno == ENOENT;
}
bool fd_snapshot(std::vector<int>& values) {
    values.clear();
    DIR* stream = opendir("/proc/self/fd");
    if (!stream) return false;
    const int own = dirfd(stream);
    errno = 0;
    while (dirent* entry = readdir(stream)) {
        int value = -1;
        if (std::sscanf(entry->d_name, "%d", &value) == 1 && value != own) values.push_back(value);
        errno = 0;
    }
    const int error = errno;
    if (closedir(stream) != 0 || error != 0) return false;
    std::sort(values.begin(), values.end());
    return true;
}
directory::HooksForTesting hooks(unsigned tag) {
    return {.creation_seed = seed(tag)};
}
bool create(const directory::HooksForTesting& config,
            directory::PrivateDirectoryLease& lease,
            directory::Diagnostic& diagnostic) {
    return directory::PrivateDirectoryLease::create_with_hooks_for_testing(
        config, lease, diagnostic);
}
bool failed(const directory::Diagnostic& value, directory::FailurePhase phase, int error) {
    return value.phase == phase && value.error_number == error;
}
bool complete(const std::shared_ptr<const directory::SettlementReceipt>& receipt) {
    return receipt && receipt->attempted && receipt->object_removed && receipt->namespace_synced &&
           receipt->descriptor_closed && receipt->settlement_complete &&
           receipt->state == directory::State::Removed &&
           receipt->original_residue == directory::Residue::Absent &&
           receipt->candidate_residue == directory::Residue::Absent;
}
std::shared_ptr<const directory::SettlementReceipt> normal(unsigned tag, bool explicit_settle) {
    directory::PrivateDirectoryLease lease;
    directory::Diagnostic diagnostic;
    if (!create(hooks(tag), lease, diagnostic)) return {};
    const auto receipt = lease.settlement_receipt();
    if (explicit_settle && (!lease.revalidate(diagnostic) || !lease.settle(diagnostic))) return {};
    return receipt;
}
int close_with_eio(int descriptor, void* opaque) {
    auto& injected = *static_cast<bool*>(opaque);
    const int result = close(descriptor);
    if (result != 0 || injected) return result;
    injected = true;
    return errno = EIO, -1;
}
bool normal_lifecycle_tests() {
    std::vector<int> before, after;
    const bool baseline = fd_snapshot(before);
    bool injected = false;
    auto config = hooks(14);
    config.close_descriptor = close_with_eio;
    config.context = &injected;
    std::shared_ptr<const directory::SettlementReceipt> receipt;
    bool causal = false;
    {
        directory::PrivateDirectoryLease lease;
        directory::Diagnostic diagnostic;
        causal = create(config, lease, diagnostic);
        receipt = lease.settlement_receipt();
        causal =
            causal && !lease.settle(diagnostic) && lease.state() == directory::State::Removed &&
            failed(diagnostic, directory::FailurePhase::Close, EIO) &&
            failed(receipt->diagnostic, directory::FailurePhase::Close, EIO) &&
            !lease.settle(diagnostic) && failed(diagnostic, directory::FailurePhase::Close, EIO);
    }
    return check(baseline && complete(normal(1, true)) && complete(normal(2, false)) && causal &&
                     injected && receipt->object_removed && !receipt->settlement_complete &&
                     failed(receipt->diagnostic, directory::FailurePhase::Close, EIO) &&
                     fd_snapshot(after) && before == after,
                 "explicit/destructor settlement and FD baseline");
}
bool creation_abort_test() {
    const int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    auto config = hooks(3);
    config.abort = directory::AbortPoint::AfterMkdir;
    directory::Identity before, after;
    std::string name;
    std::shared_ptr<const directory::SettlementReceipt> receipt;
    bool pending = false;
    {
        directory::PrivateDirectoryLease lease;
        directory::Diagnostic diagnostic;
        pending = !create(config, lease, diagnostic) &&
                  lease.state() == directory::State::Unresolved &&
                  failed(diagnostic, directory::FailurePhase::Hook, ECANCELED);
        name = lease.basename();
        receipt = lease.settlement_receipt();
        pending = pending && identity_at(parent, name, before);
    }
    pending = pending && receipt && receipt->attempted && !receipt->settlement_complete &&
              receipt->descriptor_closed &&
              receipt->original_residue == directory::Residue::Present &&
              identity_at(parent, name, after) && same(before, after) &&
              unlinkat(parent, name.c_str(), AT_REMOVEDIR) == 0;
    config = hooks(4);
    config.abort = directory::AbortPoint::AfterFirstOwnedMatch;
    directory::PrivateDirectoryLease lease;
    directory::Diagnostic diagnostic;
    const bool owned = !create(config, lease, diagnostic) &&
                       lease.state() == directory::State::Owned && lease.settle(diagnostic);
    if (parent >= 0) close(parent);
    return check(pending && owned, "pending unresolved and owned abort settleable");
}
bool replacement_restore_test() {
    directory::PrivateDirectoryLease lease;
    directory::Diagnostic diagnostic;
    if (!create(hooks(5), lease, diagnostic)) return false;
    const bool mode_restored =
        fchmod(lease.descriptor(), 0777) == 0 && !lease.revalidate(diagnostic) &&
        lease.state() == directory::State::BindingLost &&
        failed(diagnostic, directory::FailurePhase::Revalidate, ESTALE) &&
        fchmod(lease.descriptor(), 0700) == 0 && lease.revalidate(diagnostic) &&
        lease.state() == directory::State::Owned;
    const int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const std::string original = lease.basename(), saved = original + ".saved";
    directory::Identity owned, foreign, observed_owned, observed_foreign;
    const bool injected =
        mode_restored && renameat(parent, original.c_str(), parent, saved.c_str()) == 0 &&
        mkdirat(parent, original.c_str(), 0700) == 0 && identity_at(parent, saved, owned) &&
        identity_at(parent, original, foreign) && same(owned, lease.identity()) &&
        !same(owned, foreign);
    const bool refused = injected && !lease.settle(diagnostic) &&
                         lease.state() == directory::State::BindingLost &&
                         failed(diagnostic, directory::FailurePhase::Revalidate, ESTALE) &&
                         identity_at(parent, saved, observed_owned) &&
                         identity_at(parent, original, observed_foreign) &&
                         same(owned, observed_owned) && same(foreign, observed_foreign);
    const bool restored = refused && unlinkat(parent, original.c_str(), AT_REMOVEDIR) == 0 &&
                          renameat(parent, saved.c_str(), parent, original.c_str()) == 0 &&
                          lease.revalidate(diagnostic) &&
                          lease.state() == directory::State::Owned && lease.settle(diagnostic);
    if (parent >= 0) close(parent);
    return check(restored, "mode/replacement refused and exact restorations retried");
}
bool collision_retry_test() {
    auto config = hooks(7);
    config.quarantine_seeds = {seed(8), seed(9)};
    config.quarantine_seed_count = 2;
    directory::PrivateDirectoryLease lease;
    directory::Diagnostic diagnostic;
    if (!create(config, lease, diagnostic)) return false;
    const int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const std::string collision = ".rut377-directory-quarantine-" + config.quarantine_seeds[0];
    directory::Identity collision_id, observed_collision, candidate;
    const bool prepared = mkdirat(parent, collision.c_str(), 0700) == 0 &&
                          identity_at(parent, collision, collision_id) &&
                          mkdirat(lease.descriptor(), "kept", 0700) == 0;
    const bool retained = prepared && !lease.settle(diagnostic) &&
                          failed(diagnostic, directory::FailurePhase::Remove, ENOTEMPTY) &&
                          lease.state() == directory::State::Quarantined &&
                          identity_at(parent, collision, observed_collision) &&
                          identity_at(parent, lease.basename(), candidate) &&
                          same(collision_id, observed_collision) &&
                          same(candidate, lease.identity());
    const bool retried = retained && unlinkat(lease.descriptor(), "kept", AT_REMOVEDIR) == 0 &&
                         lease.settle(diagnostic) &&
                         identity_at(parent, collision, observed_collision) &&
                         same(collision_id, observed_collision) &&
                         unlinkat(parent, collision.c_str(), AT_REMOVEDIR) == 0;
    if (parent >= 0) close(parent);
    return check(retried, "collision and ENOTEMPTY same-name retry");
}
struct RenameMutation {
    std::string original, saved;
    directory::Identity object_id, foreign_id, child_id;
    bool replace_candidate = false, complete = false;
};
void mutate_after_rename(int parent, const char* candidate, void* opaque) {
    auto& value = *static_cast<RenameMutation*>(opaque);
    if (!value.replace_candidate) {
        value.complete = mkdirat(parent, value.original.c_str(), 0700) == 0 &&
                         identity_at(parent, value.original, value.foreign_id) &&
                         identity_at(parent, candidate, value.object_id) &&
                         !same(value.foreign_id, value.object_id);
        return;
    }
    value.saved = std::string(candidate) + ".saved";
    value.complete = renameat(parent, candidate, parent, value.saved.c_str()) == 0 &&
                     mkdirat(parent, candidate, 0700) == 0 &&
                     identity_at(parent, value.saved, value.object_id) &&
                     identity_at(parent, candidate, value.foreign_id);
    const int foreign = openat(parent, candidate, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    value.complete = value.complete && foreign >= 0 && mkdirat(foreign, "foreign", 0700) == 0 &&
                     identity_at(foreign, "foreign", value.child_id);
    if (foreign >= 0) close(foreign);
}
bool post_rename_mismatch_test() {
    RenameMutation mutation;
    mutation.replace_candidate = true;
    auto config = hooks(10);
    config.quarantine_seeds = {seed(11), {}};
    config.quarantine_seed_count = 1;
    config.after_quarantine_rename = mutate_after_rename;
    config.context = &mutation;
    std::shared_ptr<const directory::SettlementReceipt> receipt;
    std::string candidate;
    directory::Identity owned;
    bool unresolved = false;
    {
        directory::PrivateDirectoryLease lease;
        directory::Diagnostic diagnostic;
        if (!create(config, lease, diagnostic)) return false;
        receipt = lease.settlement_receipt();
        owned = lease.identity();
        unresolved = !lease.settle(diagnostic) && mutation.complete &&
                     failed(diagnostic, directory::FailurePhase::Quarantine, ESTALE) &&
                     lease.state() == directory::State::Unresolved;
        candidate = lease.basename();
    }
    const int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const int foreign =
        openat(parent, candidate.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    directory::Identity saved, replacement, child;
    const bool preserved =
        unresolved && receipt && !receipt->object_removed && receipt->descriptor_closed &&
        !receipt->current_basename_known &&
        receipt->candidate_residue == directory::Residue::Present &&
        failed(receipt->diagnostic, directory::FailurePhase::Quarantine, ESTALE) &&
        identity_at(parent, mutation.saved, saved) && identity_at(parent, candidate, replacement) &&
        foreign >= 0 && identity_at(foreign, "foreign", child) && same(saved, mutation.object_id) &&
        same(saved, owned) && same(replacement, mutation.foreign_id) &&
        same(child, mutation.child_id);
    const bool cleaned = preserved && unlinkat(foreign, "foreign", AT_REMOVEDIR) == 0 &&
                         unlinkat(parent, candidate.c_str(), AT_REMOVEDIR) == 0 &&
                         unlinkat(parent, mutation.saved.c_str(), AT_REMOVEDIR) == 0;
    if (foreign >= 0) close(foreign);
    if (parent >= 0) close(parent);
    return check(cleaned, "post-rename mismatch preserves exact foreign entries");
}
bool original_residue_test() {
    RenameMutation mutation;
    auto config = hooks(12);
    config.quarantine_seeds = {seed(13), {}};
    config.quarantine_seed_count = 1;
    config.after_quarantine_rename = mutate_after_rename;
    config.context = &mutation;
    directory::PrivateDirectoryLease lease;
    directory::Diagnostic diagnostic;
    if (!create(config, lease, diagnostic)) return false;
    mutation.original = lease.basename();
    const auto receipt = lease.settlement_receipt();
    const int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    directory::Identity observed;
    const bool incomplete =
        !lease.settle(diagnostic) && mutation.complete &&
        lease.state() == directory::State::Removed && receipt->object_removed &&
        !receipt->settlement_complete && !receipt->descriptor_closed && receipt->namespace_synced &&
        receipt->original_residue == directory::Residue::Present &&
        receipt->candidate_residue == directory::Residue::Absent &&
        failed(diagnostic, directory::FailurePhase::Revalidate, EEXIST) &&
        same(mutation.object_id, lease.identity()) &&
        identity_at(parent, mutation.original, observed) && same(observed, mutation.foreign_id) &&
        absent_at(parent, receipt->last_candidate);
    const bool completed = incomplete &&
                           unlinkat(parent, mutation.original.c_str(), AT_REMOVEDIR) == 0 &&
                           lease.settle(diagnostic) && complete(receipt);
    if (parent >= 0) close(parent);
    return check(completed, "foreign original residue is reported, never deleted");
}
}  // namespace
int main() {
    if (!normal_lifecycle_tests() || !creation_abort_test() || !replacement_restore_test() ||
        !collision_retry_test() || !post_rename_mismatch_test() || !original_residue_test())
        return 1;
    std::puts("PASS: #377 private directory lease");
}
