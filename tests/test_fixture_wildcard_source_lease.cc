#include "fixture_wildcard_source_lease.h"
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace source_lease = rut::test::fixture_wildcard_source_lease;
namespace listener = rut::test::fixture_privileged_listener;

namespace {

constexpr listener::ListenerPlan kPlan{0x0a010203u, 0x0a010204u, 8080u};
constexpr char kBasename[] = "wildcard-attempt.rut";

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
    return condition;
}

struct PrivateDirectory {
    std::string path;
    int fd = -1;

    bool create() {
        std::array<char, 64> pattern{};
        std::snprintf(pattern.data(), pattern.size(), "/tmp/rut377-source-XXXXXX");
        char* const created = mkdtemp(pattern.data());
        if (created == nullptr) return false;
        path = created;
        if (chmod(path.c_str(), 0700) != 0) return false;
        fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        return fd >= 0;
    }

    ~PrivateDirectory() {
        if (fd >= 0) close(fd);
        if (!path.empty() && rmdir(path.c_str()) != 0)
            std::fprintf(stderr,
                         "FAIL [#377 source test directory cleanup]: path=%s errno=%d\n",
                         path.c_str(),
                         errno);
    }
};

struct StderrCapture {
    int saved = -1;
    int reader = -1;
    int writer = -1;
    bool active = false;

    bool start() {
        int pipe_fds[2] = {-1, -1};
        saved = dup(STDERR_FILENO);
        if (saved < 0 || pipe2(pipe_fds, O_CLOEXEC) != 0) return false;
        reader = pipe_fds[0];
        writer = pipe_fds[1];
        if (dup2(writer, STDERR_FILENO) < 0) return false;
        active = true;
        return true;
    }

    bool finish(std::string& output) {
        std::fflush(stderr);
        const bool restored = active && dup2(saved, STDERR_FILENO) >= 0;
        active = false;
        if (saved >= 0) close(saved);
        saved = -1;
        if (writer >= 0) close(writer);
        writer = -1;
        std::array<char, 512> bytes{};
        const ssize_t count = reader >= 0 ? read(reader, bytes.data(), bytes.size()) : -1;
        if (reader >= 0) close(reader);
        reader = -1;
        output =
            count > 0 ? std::string(bytes.data(), static_cast<std::size_t>(count)) : std::string{};
        return restored && count >= 0;
    }

    ~StderrCapture() {
        if (active && saved >= 0) (void)dup2(saved, STDERR_FILENO);
        for (int fd : {saved, reader, writer})
            if (fd >= 0) close(fd);
    }
};

bool write_all_at(int directory, const char* name, const std::string& bytes, int flags = 0) {
    const int fd = openat(directory, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW | flags, 0600);
    if (fd < 0) return false;
    std::size_t offset = 0u;
    while (offset < bytes.size()) {
        const ssize_t count =
            pwrite(fd, bytes.data() + offset, bytes.size() - offset, static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            close(fd);
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    const bool ok = fsync(fd) == 0 && close(fd) == 0;
    return ok;
}

std::string expected_source() {
    std::string source;
    listener::Diagnostic diagnostic;
    if (!listener::build_listener_source(
            kPlan, listener::ListenerSourceKind::Wildcard, source, diagnostic))
        return {};
    return source;
}

bool replacement_intact(int directory, const char* name, const struct stat& expected) {
    struct stat current{};
    return fstatat(directory, name, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
           current.st_dev == expected.st_dev && current.st_ino == expected.st_ino;
}

struct RemovalSwap {
    bool succeeded = false;
    struct stat replacement{};
};

void replace_at_removal_boundary(int directory, const char* name, void* opaque) {
    auto& swap = *static_cast<RemovalSwap*>(opaque);
    swap.succeeded = renameat(directory, name, directory, "boundary-original.rut") == 0 &&
                     write_all_at(directory, name, expected_source(), O_CREAT | O_EXCL) &&
                     fstatat(directory, name, &swap.replacement, AT_SYMLINK_NOFOLLOW) == 0;
}

struct FifoSwap {
    bool succeeded = false;
    struct stat replacement{};
};

void replace_before_reopen_with_fifo(int directory, const char* name, void* opaque) {
    auto& swap = *static_cast<FifoSwap*>(opaque);
    swap.succeeded = renameat(directory, name, directory, "fifo-original.rut") == 0 &&
                     mkfifoat(directory, name, 0600) == 0 &&
                     fstatat(directory, name, &swap.replacement, AT_SYMLINK_NOFOLLOW) == 0;
}

struct PreadInjection {
    std::size_t expected_size = 0u;
    unsigned data_interruptions = 0u;
    unsigned trailing_interruptions = 0u;
};

PreadInjection* active_pread_injection = nullptr;

ssize_t injecting_pread(int fd, void* buffer, std::size_t count, off_t offset) {
    if (active_pread_injection != nullptr && offset == 0 &&
        active_pread_injection->data_interruptions == 0u) {
        ++active_pread_injection->data_interruptions;
        errno = EINTR;
        return -1;
    }
    if (active_pread_injection != nullptr &&
        offset == static_cast<off_t>(active_pread_injection->expected_size) &&
        active_pread_injection->trailing_interruptions == 0u) {
        ++active_pread_injection->trailing_interruptions;
        errno = EINTR;
        return -1;
    }
    return pread(fd, buffer, count, offset);
}

bool canonical_creation_test() {
    PrivateDirectory directory;
    source_lease::WildcardAttemptSourceLease lease;
    source_lease::Diagnostic diagnostic;
    bool ok = check(directory.create(), "private directory creation failed") &&
              check(source_lease::WildcardAttemptSourceLease::create(
                        directory.fd, directory.path, kBasename, kPlan, lease, diagnostic),
                    "canonical wildcard source lease creation failed") &&
              check(lease.active() && lease.path() == directory.path + "/" + kBasename &&
                        lease.basename() == kBasename && lease.descriptor() >= 0,
                    "canonical lease did not retain its exact path and descriptor");
    if (!ok) return false;
    struct stat directory_status{};
    struct stat source_status{};
    ok = check(
        fstat(directory.fd, &directory_status) == 0 &&
            fstat(lease.descriptor(), &source_status) == 0 &&
            lease.directory_identity().device ==
                static_cast<std::uint64_t>(directory_status.st_dev) &&
            lease.directory_identity().inode ==
                static_cast<std::uint64_t>(directory_status.st_ino) &&
            lease.source_identity().device == static_cast<std::uint64_t>(source_status.st_dev) &&
            lease.source_identity().inode == static_cast<std::uint64_t>(source_status.st_ino) &&
            lease.source_identity().mode == static_cast<std::uint64_t>(source_status.st_mode) &&
            lease.source_identity().uid == getuid() && lease.source_identity().gid == getgid() &&
            lease.source_identity().size == expected_source().size(),
        "canonical lease did not record complete identity metadata");
    if (!ok) return false;
    const off_t selected_offset = 7;
    ok = check(lseek(lease.descriptor(), selected_offset, SEEK_SET) == selected_offset,
               "source lease offset setup failed") &&
         check(lease.revalidate(diagnostic) && lease.revalidate(diagnostic),
               "repeated canonical source validation failed") &&
         check(lseek(lease.descriptor(), 0, SEEK_CUR) == selected_offset,
               "source revalidation changed the retained descriptor offset") &&
         check(lease.remove(diagnostic), "canonical source removal failed") &&
         check(!lease.active() && lease.descriptor() < 0 && lease.cleanup_state()->attempted &&
                   lease.cleanup_state()->succeeded,
               "canonical source removal was not observably complete");
    struct stat absent{};
    errno = 0;
    return ok && check(fstatat(directory.fd, kBasename, &absent, AT_SYMLINK_NOFOLLOW) < 0 &&
                           errno == ENOENT,
                       "canonical source pathname remained after removal");
}

bool exact_bytes_creation_and_bounds_test() {
    PrivateDirectory directory;
    source_lease::Diagnostic diagnostic;
    if (!directory.create()) return check(false, "exact source directory setup failed");

    constexpr char exact[] = "listen :0\nroute GET \"/\" { return 204 }\n";
    source_lease::WildcardAttemptSourceLease canonical;
    bool ok = check(source_lease::WildcardAttemptSourceLease::create_exact_bytes(
                        directory.fd, directory.path, "exact.rut", exact, canonical, diagnostic) &&
                        canonical.source_identity().size == sizeof(exact) - 1u &&
                        canonical.revalidate(diagnostic),
                    "bounded exact source creation failed");

    source_lease::WildcardAttemptSourceLease empty;
    ok = check(!source_lease::WildcardAttemptSourceLease::create_exact_bytes(
                   directory.fd, directory.path, "empty.rut", "", empty, diagnostic) &&
                   diagnostic.phase == source_lease::FailurePhase::Argument &&
                   diagnostic.error_number == EINVAL,
               "empty exact source was accepted") &&
         ok;

    source_lease::WildcardAttemptSourceLease embedded_nul;
    const std::string nul_bytes("a\0b", 3u);
    ok = check(!source_lease::WildcardAttemptSourceLease::create_exact_bytes(
                   directory.fd, directory.path, "nul.rut", nul_bytes, embedded_nul, diagnostic) &&
                   diagnostic.phase == source_lease::FailurePhase::Argument &&
                   diagnostic.error_number == EINVAL,
               "embedded-NUL exact source was accepted") &&
         ok;

    source_lease::WildcardAttemptSourceLease over;
    const std::string over_bytes(256u, 'x');
    ok = check(!source_lease::WildcardAttemptSourceLease::create_exact_bytes(
                   directory.fd, directory.path, "over.rut", over_bytes, over, diagnostic) &&
                   diagnostic.phase == source_lease::FailurePhase::Argument &&
                   diagnostic.error_number == EINVAL,
               "over-bound exact source was accepted") &&
         ok;

    source_lease::WildcardAttemptSourceLease boundary;
    const std::string boundary_bytes(255u, 'x');
    ok = check(source_lease::WildcardAttemptSourceLease::create_exact_bytes(directory.fd,
                                                                            directory.path,
                                                                            "boundary.rut",
                                                                            boundary_bytes,
                                                                            boundary,
                                                                            diagnostic) &&
                   boundary.revalidate(diagnostic),
               "255-byte exact source boundary was rejected") &&
         ok;

    source_lease::WildcardAttemptSourceLease poisoned_owner;
    std::string caller_owned = "owned exact source bytes\n";
    const std::string expected_caller_bytes = caller_owned;
    const bool poison_created =
        source_lease::WildcardAttemptSourceLease::create_exact_bytes(directory.fd,
                                                                     directory.path,
                                                                     "poisoned-owner.rut",
                                                                     caller_owned,
                                                                     poisoned_owner,
                                                                     diagnostic);
    caller_owned.assign(caller_owned.size(), 'z');
    std::array<char, 64> leased_bytes{};
    const ssize_t leased_count =
        poison_created
            ? pread(poisoned_owner.descriptor(), leased_bytes.data(), leased_bytes.size(), 0)
            : -1;
    ok = check(poison_created && caller_owned != expected_caller_bytes &&
                   poisoned_owner.revalidate(diagnostic) && leased_count >= 0 &&
                   std::string(leased_bytes.data(), static_cast<std::size_t>(leased_count)) ==
                       expected_caller_bytes,
               "caller exact-byte poisoning changed leased source") &&
         ok;
    return check(canonical.remove(diagnostic) && boundary.remove(diagnostic) &&
                     poisoned_owner.remove(diagnostic),
                 "exact source cleanup failed") &&
           ok;
}

bool embedded_nul_rejection_test() {
    PrivateDirectory directory;
    if (!directory.create()) return check(false, "embedded-NUL directory setup failed");

    source_lease::Diagnostic diagnostic;
    source_lease::WildcardAttemptSourceLease path_lease;
    const std::string nul_path = directory.path + std::string("\0suffix", 7u);
    const bool path_rejected =
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, nul_path, kBasename, kPlan, path_lease, diagnostic) &&
        diagnostic.phase == source_lease::FailurePhase::Argument &&
        diagnostic.error_number == EINVAL;

    source_lease::WildcardAttemptSourceLease basename_lease;
    const std::string nul_basename("wildcard\0replacement.rut", 24u);
    const bool basename_rejected =
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, nul_basename, kPlan, basename_lease, diagnostic) &&
        diagnostic.phase == source_lease::FailurePhase::Argument &&
        diagnostic.error_number == EINVAL;

    struct stat absent{};
    errno = 0;
    return check(path_rejected && basename_rejected &&
                     fstatat(directory.fd, kBasename, &absent, AT_SYMLINK_NOFOLLOW) < 0 &&
                     errno == ENOENT,
                 "embedded NUL path or basename was not rejected before creation");
}

bool removal_boundary_replacement_test() {
    PrivateDirectory directory;
    source_lease::WildcardAttemptSourceLease lease;
    source_lease::Diagnostic diagnostic;
    if (!directory.create() ||
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, kBasename, kPlan, lease, diagnostic))
        return check(false, "removal-boundary replacement setup failed");

    RemovalSwap swap;
    const bool refused =
        !lease.remove_with_hook_for_testing(replace_at_removal_boundary, &swap, diagnostic);
    const bool replacement_preserved =
        swap.succeeded && diagnostic.phase == source_lease::FailurePhase::Quarantine &&
        diagnostic.error_number == ESTALE &&
        replacement_intact(directory.fd, kBasename, swap.replacement);
    if (unlinkat(directory.fd, kBasename, 0) != 0 ||
        renameat(directory.fd, "boundary-original.rut", directory.fd, kBasename) != 0)
        return check(false, "removal-boundary replacement restoration failed");
    return check(refused && replacement_preserved,
                 "atomic quarantine deleted or accepted the causal replacement") &&
           check(lease.revalidate(diagnostic) && lease.remove(diagnostic),
                 "restored causal-removal source did not clean up exactly");
}

bool fifo_reopen_is_bounded_test() {
    PrivateDirectory directory;
    StderrCapture capture;
    if (!directory.create() || !capture.start())
        return check(false, "FIFO reopen capture setup failed");

    FifoSwap swap;
    auto cleanup = std::shared_ptr<const source_lease::CleanupState>{};
    bool rejected = false;
    {
        source_lease::WildcardAttemptSourceLease lease;
        source_lease::Diagnostic diagnostic;
        const source_lease::SourceLeaseHooksForTesting hooks{replace_before_reopen_with_fifo,
                                                             &swap};
        const auto started = std::chrono::steady_clock::now();
        const bool created =
            source_lease::WildcardAttemptSourceLease::create_with_hooks_for_testing(
                directory.fd, directory.path, kBasename, kPlan, hooks, lease, diagnostic);
        const auto elapsed = std::chrono::steady_clock::now() - started;
        cleanup = lease.cleanup_state();
        rejected = !created && swap.succeeded && S_ISFIFO(swap.replacement.st_mode) &&
                   elapsed < std::chrono::seconds(1) && cleanup && cleanup->attempted &&
                   !cleanup->succeeded &&
                   replacement_intact(directory.fd, kBasename, swap.replacement);
        if (unlinkat(directory.fd, kBasename, 0) != 0 ||
            unlinkat(directory.fd, "fifo-original.rut", 0) != 0)
            rejected = false;
    }
    std::string captured;
    const bool captured_ok = capture.finish(captured);
    return check(rejected && captured_ok &&
                     captured.find("#377 wildcard source lease destructor") != std::string::npos,
                 "FIFO replacement did not reject promptly with observable cleanup uncertainty");
}

bool pread_eintr_retry_test() {
    PrivateDirectory directory;
    source_lease::WildcardAttemptSourceLease lease;
    source_lease::Diagnostic diagnostic;
    if (!directory.create() ||
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, kBasename, kPlan, lease, diagnostic))
        return check(false, "pread EINTR setup failed");

    PreadInjection injection{expected_source().size(), 0u, 0u};
    active_pread_injection = &injection;
    const bool read = source_lease::read_exact_bytes_for_testing(
        lease.descriptor(), expected_source(), injecting_pread, diagnostic);
    active_pread_injection = nullptr;
    return check(
               read && injection.data_interruptions == 1u && injection.trailing_interruptions == 1u,
               "shared exact pread helper did not retry data and trailing EINTR") &&
           check(lease.remove(diagnostic), "pread EINTR source cleanup failed");
}

bool rename_replacement_test() {
    PrivateDirectory directory;
    source_lease::WildcardAttemptSourceLease lease;
    source_lease::Diagnostic diagnostic;
    if (!directory.create() ||
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, kBasename, kPlan, lease, diagnostic))
        return check(false, "rename test setup failed");
    constexpr char moved[] = "moved-original.rut";
    const std::string bytes = expected_source();
    if (renameat(directory.fd, kBasename, directory.fd, moved) != 0 ||
        !write_all_at(directory.fd, kBasename, bytes, O_CREAT | O_EXCL))
        return check(false, "rename/replacement mutation setup failed");
    struct stat replacement{};
    if (fstatat(directory.fd, kBasename, &replacement, AT_SYMLINK_NOFOLLOW) != 0)
        return check(false, "rename replacement identity setup failed");
    const bool ok =
        check(!lease.revalidate(diagnostic),
              "renamed pathname replacement passed canonical validation") &&
        check(!lease.remove(diagnostic), "removal accepted a renamed pathname replacement") &&
        check(replacement_intact(directory.fd, kBasename, replacement),
              "refused removal changed the renamed replacement");
    if (unlinkat(directory.fd, kBasename, 0) != 0 ||
        renameat(directory.fd, moved, directory.fd, kBasename) != 0)
        return check(false, "rename test restoration failed");
    return ok && check(lease.remove(diagnostic), "restored renamed source did not remove exactly");
}

bool in_place_bytes_test() {
    PrivateDirectory directory;
    source_lease::WildcardAttemptSourceLease lease;
    source_lease::Diagnostic diagnostic;
    if (!directory.create() ||
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, kBasename, kPlan, lease, diagnostic))
        return check(false, "in-place byte test setup failed");
    std::string mutation = expected_source();
    mutation[mutation.find(":8080")] = ';';
    const bool mutated = write_all_at(directory.fd, kBasename, mutation);
    const bool rejected = check(mutated && !lease.revalidate(diagnostic) &&
                                    diagnostic.phase == source_lease::FailurePhase::Bytes,
                                "same-inode/same-size byte rewrite passed validation");
    return rejected &&
           check(write_all_at(directory.fd, kBasename, expected_source()),
                 "in-place byte restoration failed") &&
           check(lease.remove(diagnostic), "restored in-place source did not remove exactly");
}

bool unlink_recreate_and_removal_refusal_test() {
    PrivateDirectory directory;
    StderrCapture capture;
    if (!directory.create() || !capture.start())
        return check(false, "unlink/recreate capture setup failed");
    auto cleanup = std::shared_ptr<const source_lease::CleanupState>{};
    bool scenario_ok = false;
    {
        source_lease::WildcardAttemptSourceLease lease;
        source_lease::Diagnostic diagnostic;
        const bool created = source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, kBasename, kPlan, lease, diagnostic);
        cleanup = lease.cleanup_state();
        struct stat replacement{};
        const bool replaced =
            created && unlinkat(directory.fd, kBasename, 0) == 0 &&
            write_all_at(directory.fd, kBasename, expected_source(), O_CREAT | O_EXCL) &&
            fstatat(directory.fd, kBasename, &replacement, AT_SYMLINK_NOFOLLOW) == 0;
        scenario_ok = replaced && !lease.revalidate(diagnostic) && !lease.remove(diagnostic) &&
                      replacement_intact(directory.fd, kBasename, replacement) &&
                      unlinkat(directory.fd, kBasename, 0) == 0;
    }
    std::string captured;
    const bool captured_ok = capture.finish(captured);
    return check(scenario_ok && captured_ok && cleanup && cleanup->attempted &&
                     !cleanup->succeeded &&
                     captured.find("#377 wildcard source lease destructor") != std::string::npos,
                 "unlink/recreate refusal or observable cleanup failure was incomplete");
}

bool symlink_replacement_test() {
    PrivateDirectory directory;
    source_lease::WildcardAttemptSourceLease lease;
    source_lease::Diagnostic diagnostic;
    constexpr char moved[] = "symlink-original.rut";
    if (!directory.create() ||
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, kBasename, kPlan, lease, diagnostic) ||
        renameat(directory.fd, kBasename, directory.fd, moved) != 0 ||
        symlinkat("missing-target", directory.fd, kBasename) != 0)
        return check(false, "symlink replacement mutation setup failed");
    struct stat replacement{};
    if (fstatat(directory.fd, kBasename, &replacement, AT_SYMLINK_NOFOLLOW) != 0)
        return check(false, "symlink replacement identity setup failed");
    const bool ok = check(S_ISLNK(replacement.st_mode) && !lease.revalidate(diagnostic),
                          "symlink replacement passed canonical validation") &&
                    check(!lease.remove(diagnostic), "removal accepted a symlink replacement") &&
                    check(replacement_intact(directory.fd, kBasename, replacement),
                          "refused removal deleted the symlink replacement");
    if (unlinkat(directory.fd, kBasename, 0) != 0)
        return check(false, "symlink replacement cleanup failed");
    return ok && check(renameat(directory.fd, moved, directory.fd, kBasename) == 0 &&
                           lease.revalidate(diagnostic) && lease.remove(diagnostic),
                       "symlink replacement original lease restoration failed");
}

bool metadata_and_hardlink_test() {
    PrivateDirectory directory;
    source_lease::WildcardAttemptSourceLease lease;
    source_lease::Diagnostic diagnostic;
    if (!directory.create() ||
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, kBasename, kPlan, lease, diagnostic))
        return check(false, "metadata mutation test setup failed");
    bool ok =
        check(fchmodat(directory.fd, kBasename, 0640, 0) == 0 && !lease.revalidate(diagnostic),
              "source mode mutation passed validation") &&
        check(fchmodat(directory.fd, kBasename, 0600, 0) == 0 && lease.revalidate(diagnostic),
              "restored source mode did not revalidate") &&
        check(linkat(directory.fd, kBasename, directory.fd, "hardlink.rut", 0) == 0 &&
                  !lease.revalidate(diagnostic),
              "hardlink ambiguity passed validation") &&
        check(unlinkat(directory.fd, "hardlink.rut", 0) == 0 && lease.revalidate(diagnostic),
              "hardlink removal did not restore canonical identity");
    return ok && check(lease.remove(diagnostic), "metadata test source removal failed");
}

bool length_mutation_test(bool truncate_source) {
    PrivateDirectory directory;
    source_lease::WildcardAttemptSourceLease lease;
    source_lease::Diagnostic diagnostic;
    if (!directory.create() ||
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, kBasename, kPlan, lease, diagnostic))
        return check(false, "length mutation test setup failed");
    const std::string bytes = expected_source();
    const int fd = openat(directory.fd, kBasename, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return check(false, "length mutation open failed");
    bool mutated = false;
    if (truncate_source) {
        mutated = ftruncate(fd, static_cast<off_t>(bytes.size() - 1u)) == 0;
    } else {
        const char extra = '!';
        mutated = pwrite(fd, &extra, 1u, static_cast<off_t>(bytes.size())) == 1;
    }
    mutated = mutated && fsync(fd) == 0 && close(fd) == 0;
    const bool rejected = check(mutated && !lease.revalidate(diagnostic),
                                truncate_source ? "truncated source passed validation"
                                                : "extra source byte passed validation");
    return rejected &&
           check(write_all_at(directory.fd, kBasename, bytes, O_TRUNC),
                 "length mutation restoration failed") &&
           check(lease.remove(diagnostic), "restored length source did not remove exactly");
}

bool distinct_identical_sources_test() {
    PrivateDirectory directory;
    source_lease::WildcardAttemptSourceLease first;
    source_lease::WildcardAttemptSourceLease second;
    source_lease::Diagnostic diagnostic;
    bool ok = check(directory.create(), "distinct source directory setup failed") &&
              check(source_lease::WildcardAttemptSourceLease::create(
                        directory.fd, directory.path, "first.rut", kPlan, first, diagnostic),
                    "first identical source creation failed") &&
              check(source_lease::WildcardAttemptSourceLease::create(
                        directory.fd, directory.path, "second.rut", kPlan, second, diagnostic),
                    "second identical source creation failed") &&
              check(first.source_identity().inode != second.source_identity().inode &&
                        !first.same_source_identity(second),
                    "byte-identical separate sources were accepted as one identity");
    return ok && check(first.remove(diagnostic) && second.remove(diagnostic),
                       "distinct identical source cleanup failed");
}

bool detached_lease_test() {
    PrivateDirectory directory;
    StderrCapture capture;
    if (!directory.create() || !capture.start())
        return check(false, "detached source capture setup failed");
    auto cleanup = std::shared_ptr<const source_lease::CleanupState>{};
    bool scenario_ok = false;
    {
        source_lease::WildcardAttemptSourceLease lease;
        source_lease::Diagnostic diagnostic;
        const bool created = source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, kBasename, kPlan, lease, diagnostic);
        cleanup = lease.cleanup_state();
        scenario_ok = created && unlinkat(directory.fd, kBasename, 0) == 0 &&
                      !lease.revalidate(diagnostic) &&
                      lease.validate_detached_after_unlink(diagnostic);
    }
    std::string captured;
    const bool captured_ok = capture.finish(captured);
    return check(scenario_ok && captured_ok && cleanup && cleanup->attempted &&
                     !cleanup->succeeded &&
                     cleanup->diagnostic.phase != source_lease::FailurePhase::None &&
                     captured.find("#377 wildcard source lease destructor") != std::string::npos,
                 "detached lease or destructor cleanup refusal was not observably fail-closed");
}

}  // namespace

int main() {
    const bool ok =
        canonical_creation_test() && exact_bytes_creation_and_bounds_test() &&
        embedded_nul_rejection_test() && removal_boundary_replacement_test() &&
        fifo_reopen_is_bounded_test() && pread_eintr_retry_test() && rename_replacement_test() &&
        in_place_bytes_test() && unlink_recreate_and_removal_refusal_test() &&
        symlink_replacement_test() && metadata_and_hardlink_test() && length_mutation_test(true) &&
        length_mutation_test(false) && distinct_identical_sources_test() && detached_lease_test();
    if (!ok) return 1;
    std::puts("PASS: #377 immutable wildcard-attempt source lease");
    return 0;
}
