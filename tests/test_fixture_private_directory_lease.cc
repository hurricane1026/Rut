#include "fixture_private_directory_lease.h"
#include <array>
#include <cerrno>
#include <cstdio>
#include <memory>
#include <string>

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
std::string quarantine(const std::string& value) {
    return ".rut377-directory-quarantine-" + value;
}
struct ObjectIdentity {
    std::uint64_t device = 0, inode = 0;
};
bool identity_at(int parent, const std::string& name, ObjectIdentity& identity) {
    struct stat status{};
    if (fstatat(parent, name.c_str(), &status, AT_SYMLINK_NOFOLLOW) != 0) return false;
    identity = {static_cast<std::uint64_t>(status.st_dev),
                static_cast<std::uint64_t>(status.st_ino)};
    return true;
}
bool same(const ObjectIdentity& left, const ObjectIdentity& right) {
    return left.device == right.device && left.inode == right.inode;
}
bool same(const ObjectIdentity& value, const directory::Identity& lease) {
    return value.device == lease.device && value.inode == lease.inode;
}
bool absent_at(int parent, const std::string& name) {
    ObjectIdentity unused;
    errno = 0;
    return !identity_at(parent, name, unused) && errno == ENOENT;
}
bool fd_count(unsigned& count) {
    DIR* stream = opendir("/proc/self/fd");
    if (!stream) return false;
    count = 0;
    while (dirent* entry = readdir(stream))
        if (entry->d_name[0] != '.') ++count;
    --count;
    return closedir(stream) == 0;
}
directory::HooksForTesting hooks(unsigned tag) {
    directory::HooksForTesting value;
    value.creation_seed = seed(tag);
    return value;
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
bool normal_lifecycle_tests() {
    unsigned before = 0, after = 0;
    const bool baseline = fd_count(before);
    const auto explicit_receipt = normal(1, true);
    const auto destructor_receipt = normal(2, false);
    return check(baseline && complete(explicit_receipt) && complete(destructor_receipt) &&
                     fd_count(after) && before == after,
                 "explicit/destructor settlement and FD baseline");
}
bool creation_abort_test() {
    const int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    auto config = hooks(3);
    config.abort = directory::AbortPoint::AfterMkdir;
    ObjectIdentity before, after;
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
    const int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const std::string original = lease.basename(), saved = original + ".saved";
    ObjectIdentity owned, foreign, observed_owned, observed_foreign;
    const bool injected = renameat(parent, original.c_str(), parent, saved.c_str()) == 0 &&
                          mkdirat(parent, original.c_str(), 0700) == 0 &&
                          identity_at(parent, saved, owned) &&
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
    return check(restored, "replacement refused, exact restoration retried");
}
bool mode_restore_test() {
    directory::PrivateDirectoryLease lease;
    directory::Diagnostic diagnostic;
    bool ok = create(hooks(6), lease, diagnostic);
    ok = ok && fchmod(lease.descriptor(), 0777) == 0 && !lease.revalidate(diagnostic) &&
         lease.state() == directory::State::BindingLost &&
         failed(diagnostic, directory::FailurePhase::Revalidate, ESTALE) &&
         fchmod(lease.descriptor(), 0700) == 0 && lease.revalidate(diagnostic) &&
         lease.state() == directory::State::Owned && lease.settle(diagnostic);
    return check(ok, "non-private mode refused and exact mode restored");
}
bool collision_retry_test() {
    auto config = hooks(7);
    config.quarantine_seeds = {seed(8), seed(9)};
    config.quarantine_seed_count = 2;
    directory::PrivateDirectoryLease lease;
    directory::Diagnostic diagnostic;
    if (!create(config, lease, diagnostic)) return false;
    const int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const std::string collision = quarantine(config.quarantine_seeds[0]);
    ObjectIdentity collision_id, observed_collision, candidate;
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
    std::string saved;
    ObjectIdentity saved_id, foreign_id, child_id;
    bool complete = false;
};
void replace_after_rename(int parent, const char* candidate, void* opaque) {
    auto& value = *static_cast<RenameMutation*>(opaque);
    value.saved = std::string(candidate) + ".saved";
    value.complete = renameat(parent, candidate, parent, value.saved.c_str()) == 0 &&
                     mkdirat(parent, candidate, 0700) == 0 &&
                     identity_at(parent, value.saved, value.saved_id) &&
                     identity_at(parent, candidate, value.foreign_id);
    const int foreign = openat(parent, candidate, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    value.complete = value.complete && foreign >= 0 && mkdirat(foreign, "foreign", 0700) == 0 &&
                     identity_at(foreign, "foreign", value.child_id);
    if (foreign >= 0) close(foreign);
}
bool post_rename_mismatch_test() {
    RenameMutation mutation;
    auto config = hooks(10);
    config.quarantine_seeds = {seed(11), {}};
    config.quarantine_seed_count = 1;
    config.after_quarantine_rename = replace_after_rename;
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
    ObjectIdentity saved, replacement, child;
    const bool preserved =
        unresolved && receipt && !receipt->object_removed && receipt->descriptor_closed &&
        !receipt->current_basename_known &&
        receipt->candidate_residue == directory::Residue::Present &&
        failed(receipt->diagnostic, directory::FailurePhase::Quarantine, ESTALE) &&
        identity_at(parent, mutation.saved, saved) && identity_at(parent, candidate, replacement) &&
        foreign >= 0 && identity_at(foreign, "foreign", child) && same(saved, mutation.saved_id) &&
        same(saved, owned) && same(replacement, mutation.foreign_id) &&
        same(child, mutation.child_id);
    const bool cleaned = preserved && unlinkat(foreign, "foreign", AT_REMOVEDIR) == 0 &&
                         unlinkat(parent, candidate.c_str(), AT_REMOVEDIR) == 0 &&
                         unlinkat(parent, mutation.saved.c_str(), AT_REMOVEDIR) == 0;
    if (foreign >= 0) close(foreign);
    if (parent >= 0) close(parent);
    return check(cleaned, "post-rename mismatch preserves exact foreign entries");
}
struct OriginalMutation {
    std::string original;
    ObjectIdentity original_id, candidate_id;
    bool complete = false;
};
void replace_original(int parent, const char* candidate, void* opaque) {
    auto& value = *static_cast<OriginalMutation*>(opaque);
    value.complete = mkdirat(parent, value.original.c_str(), 0700) == 0 &&
                     identity_at(parent, value.original, value.original_id) &&
                     identity_at(parent, candidate, value.candidate_id) &&
                     !same(value.original_id, value.candidate_id);
}
bool original_residue_test() {
    OriginalMutation mutation;
    auto config = hooks(12);
    config.quarantine_seeds = {seed(13), {}};
    config.quarantine_seed_count = 1;
    config.after_quarantine_rename = replace_original;
    config.context = &mutation;
    directory::PrivateDirectoryLease lease;
    directory::Diagnostic diagnostic;
    if (!create(config, lease, diagnostic)) return false;
    mutation.original = lease.basename();
    const auto receipt = lease.settlement_receipt();
    const int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    ObjectIdentity observed;
    const bool incomplete =
        !lease.settle(diagnostic) && mutation.complete &&
        lease.state() == directory::State::Removed && receipt->object_removed &&
        !receipt->settlement_complete && !receipt->descriptor_closed && receipt->namespace_synced &&
        receipt->original_residue == directory::Residue::Present &&
        receipt->candidate_residue == directory::Residue::Absent &&
        failed(diagnostic, directory::FailurePhase::Revalidate, EEXIST) &&
        same(mutation.candidate_id, lease.identity()) &&
        identity_at(parent, mutation.original, observed) && same(observed, mutation.original_id) &&
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
        !mode_restore_test() || !collision_retry_test() || !post_rename_mismatch_test() ||
        !original_residue_test())
        return 1;
    std::puts("PASS: #377 private directory lease");
}
