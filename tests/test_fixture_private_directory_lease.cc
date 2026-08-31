#include "fixture_private_directory_lease.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstring>
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

std::string quarantine_name(const std::string& value) {
    return ".rut377-directory-quarantine-" + value;
}

bool present_at(int parent, const std::string& name) {
    struct stat status{};
    return fstatat(parent, name.c_str(), &status, AT_SYMLINK_NOFOLLOW) == 0;
}

bool absent_path(const std::string& path) {
    struct stat status{};
    errno = 0;
    return lstat(path.c_str(), &status) != 0 && errno == ENOENT;
}

bool fd_snapshot(std::vector<int>& values) {
    values.clear();
    DIR* stream = opendir("/proc/self/fd");
    if (!stream) return false;
    const int own = dirfd(stream);
    errno = 0;
    while (dirent* entry = readdir(stream)) {
        int value = -1;
        const char* end = entry->d_name + std::strlen(entry->d_name);
        const auto parsed = std::from_chars(entry->d_name, end, value);
        if (parsed.ec == std::errc{} && parsed.ptr == end && value >= 0 && value != own)
            values.push_back(value);
        errno = 0;
    }
    const int error = errno;
    const bool closed = closedir(stream) == 0;
    std::sort(values.begin(), values.end());
    return error == 0 && closed;
}

directory::HooksForTesting hooks(const std::string& creation) {
    directory::HooksForTesting value;
    value.creation_seed = creation.c_str();
    return value;
}

bool happy_and_fd_test() {
    std::vector<int> before;
    std::vector<int> after;
    const std::string creation = seed(1);
    std::string path;
    std::shared_ptr<const directory::SettlementReceipt> receipt;
    bool result = fd_snapshot(before);
    {
        directory::PrivateDirectoryLease lease;
        directory::Diagnostic diagnostic;
        result = result && directory::PrivateDirectoryLease::create_with_hooks_for_testing(
                               hooks(creation), lease, diagnostic);
        path = lease.path();
        receipt = lease.settlement_receipt();
        result = result && lease.state() == directory::State::Owned && lease.descriptor() >= 0 &&
                 lease.revalidate(diagnostic) && lease.settle(diagnostic);
    }
    return check(result && receipt && receipt->attempted && receipt->object_removed &&
                     receipt->descriptor_closed && receipt->residue == directory::Residue::Absent &&
                     receipt->state == directory::State::Removed && absent_path(path) &&
                     fd_snapshot(after) && before == after,
                 "happy settlement and FD baseline");
}

bool destructor_receipt_test() {
    const std::string creation = seed(2);
    std::string path;
    std::shared_ptr<const directory::SettlementReceipt> receipt;
    {
        directory::PrivateDirectoryLease lease;
        directory::Diagnostic diagnostic;
        if (!directory::PrivateDirectoryLease::create_with_hooks_for_testing(
                hooks(creation), lease, diagnostic))
            return false;
        path = lease.path();
        receipt = lease.settlement_receipt();
    }
    return check(receipt && receipt->attempted && receipt->object_removed &&
                     receipt->descriptor_closed && receipt->residue == directory::Residue::Absent &&
                     receipt->state == directory::State::Removed && absent_path(path),
                 "destructor receipt");
}

bool creation_abort_tests() {
    const std::string pending_seed = seed(3);
    std::string pending_name;
    std::shared_ptr<const directory::SettlementReceipt> pending_receipt;
    bool pending_failed = false;
    {
        directory::HooksForTesting config = hooks(pending_seed);
        config.abort = directory::AbortPoint::AfterMkdir;
        directory::PrivateDirectoryLease lease;
        directory::Diagnostic diagnostic;
        pending_failed = !directory::PrivateDirectoryLease::create_with_hooks_for_testing(
                             config, lease, diagnostic) &&
                         lease.state() == directory::State::Unresolved &&
                         diagnostic.phase == directory::FailurePhase::Hook;
        pending_name = lease.basename();
        pending_receipt = lease.settlement_receipt();
    }
    const int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const bool observed = parent >= 0 && pending_receipt && pending_receipt->descriptor_closed &&
                          pending_receipt->residue == directory::Residue::Present &&
                          present_at(parent, pending_name);
    const bool pending_removed =
        observed && unlinkat(parent, pending_name.c_str(), AT_REMOVEDIR) == 0;
    if (parent >= 0) close(parent);

    const std::string owned_seed = seed(4);
    directory::HooksForTesting config = hooks(owned_seed);
    config.abort = directory::AbortPoint::AfterFirstOwnedMatch;
    directory::PrivateDirectoryLease lease;
    directory::Diagnostic diagnostic;
    const bool owned_failed = !directory::PrivateDirectoryLease::create_with_hooks_for_testing(
                                  config, lease, diagnostic) &&
                              lease.state() == directory::State::Owned && lease.settle(diagnostic);
    return check(pending_failed && pending_removed && owned_failed,
                 "pending/owned acquisition abort states");
}

bool replacement_restore_test() {
    const std::string creation = seed(5);
    directory::PrivateDirectoryLease lease;
    directory::Diagnostic diagnostic;
    if (!directory::PrivateDirectoryLease::create_with_hooks_for_testing(
            hooks(creation), lease, diagnostic))
        return false;
    const std::string original = lease.basename();
    const std::string saved = original + ".saved";
    const int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const bool injected = parent >= 0 &&
                          renameat(parent, original.c_str(), parent, saved.c_str()) == 0 &&
                          mkdirat(parent, original.c_str(), 0700) == 0;
    const bool refused = injected && !lease.settle(diagnostic) &&
                         lease.state() == directory::State::BindingLost &&
                         present_at(parent, original) && present_at(parent, saved);
    const bool restored = refused && unlinkat(parent, original.c_str(), AT_REMOVEDIR) == 0 &&
                          renameat(parent, saved.c_str(), parent, original.c_str()) == 0 &&
                          lease.revalidate(diagnostic) &&
                          lease.state() == directory::State::Owned && lease.settle(diagnostic);
    if (parent >= 0) close(parent);
    return check(restored, "replacement refusal and exact restoration retry");
}

bool collision_and_enotempty_test() {
    const std::string creation = seed(6);
    const std::string collision_seed = seed(7);
    const std::string unique_seed = seed(8);
    directory::HooksForTesting config = hooks(creation);
    config.quarantine_seeds = {collision_seed.c_str(), unique_seed.c_str()};
    config.quarantine_seed_count = 2;
    directory::PrivateDirectoryLease lease;
    directory::Diagnostic diagnostic;
    if (!directory::PrivateDirectoryLease::create_with_hooks_for_testing(config, lease, diagnostic))
        return false;
    const int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const std::string collision = quarantine_name(collision_seed);
    const std::string unique = quarantine_name(unique_seed);
    const bool prepared = parent >= 0 && mkdirat(parent, collision.c_str(), 0700) == 0 &&
                          mkdirat(lease.descriptor(), "kept", 0700) == 0;
    const bool retained = prepared && !lease.settle(diagnostic) && errno == ENOTEMPTY &&
                          lease.state() == directory::State::Quarantined &&
                          lease.basename() == unique && present_at(parent, collision);
    const bool retried = retained && unlinkat(lease.descriptor(), "kept", AT_REMOVEDIR) == 0 &&
                         lease.settle(diagnostic) && present_at(parent, collision) &&
                         unlinkat(parent, collision.c_str(), AT_REMOVEDIR) == 0;
    if (parent >= 0) close(parent);
    return check(retried, "quarantine collision and same-name ENOTEMPTY retry");
}

struct RenameMutation {
    std::string saved;
    bool complete = false;
};

void replace_after_rename(int parent, const char* candidate, void* opaque) {
    auto& context = *static_cast<RenameMutation*>(opaque);
    context.saved = std::string(candidate) + ".saved";
    context.complete = renameat(parent, candidate, parent, context.saved.c_str()) == 0 &&
                       mkdirat(parent, candidate, 0700) == 0;
    const int foreign = openat(parent, candidate, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    context.complete = context.complete && foreign >= 0 && mkdirat(foreign, "foreign", 0700) == 0;
    if (foreign >= 0) close(foreign);
}

bool post_rename_mismatch_test() {
    const std::string creation = seed(9);
    const std::string quarantine_seed = seed(10);
    RenameMutation mutation;
    directory::HooksForTesting config = hooks(creation);
    config.quarantine_seeds = {quarantine_seed.c_str(), nullptr};
    config.quarantine_seed_count = 1;
    config.after_quarantine_rename = replace_after_rename;
    config.context = &mutation;
    std::shared_ptr<const directory::SettlementReceipt> receipt;
    std::string candidate;
    bool unresolved = false;
    {
        directory::PrivateDirectoryLease lease;
        directory::Diagnostic diagnostic;
        if (!directory::PrivateDirectoryLease::create_with_hooks_for_testing(
                config, lease, diagnostic))
            return false;
        receipt = lease.settlement_receipt();
        unresolved = !lease.settle(diagnostic) && mutation.complete &&
                     lease.state() == directory::State::Unresolved;
        candidate = lease.basename();
    }
    const int parent = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const int foreign =
        parent < 0
            ? -1
            : openat(parent, candidate.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const bool preserved =
        unresolved && receipt && !receipt->object_removed && receipt->descriptor_closed &&
        receipt->residue == directory::Residue::Present && receipt->last_candidate == candidate &&
        foreign >= 0 && present_at(parent, mutation.saved) && present_at(foreign, "foreign");
    const bool cleaned = preserved && unlinkat(foreign, "foreign", AT_REMOVEDIR) == 0 &&
                         unlinkat(parent, candidate.c_str(), AT_REMOVEDIR) == 0 &&
                         unlinkat(parent, mutation.saved.c_str(), AT_REMOVEDIR) == 0;
    if (foreign >= 0) close(foreign);
    if (parent >= 0) close(parent);
    return check(cleaned, "post-rename mismatch is terminal and preserves foreign entries");
}

}  // namespace

int main() {
    if (!happy_and_fd_test() || !destructor_receipt_test() || !creation_abort_tests() ||
        !replacement_restore_test() || !collision_and_enotempty_test() ||
        !post_rename_mismatch_test())
        return 1;
    std::puts("PASS: #377 private directory lease");
    return 0;
}
