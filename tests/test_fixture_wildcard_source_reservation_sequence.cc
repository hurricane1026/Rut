#include "fixture_exact_tcp_reservation_lease.h"
#include "fixture_private_directory_lease.h"
#include "fixture_wildcard_source_lease.h"
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace directory = rut::test::fixture_private_directory_lease;
namespace reservation = rut::test::fixture_exact_tcp_reservation_lease;
namespace source = rut::test::fixture_wildcard_source_lease;
namespace {

using Snapshot = std::map<int, std::string>;
constexpr char kBasename[] = "attempt.rut";

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
    return condition;
}

bool snapshot(Snapshot& result) {
    result.clear();
    DIR* stream = opendir("/proc/self/fd");
    if (stream == nullptr) return false;
    const int own = dirfd(stream);
    bool valid = own >= 0;
    errno = 0;
    while (valid) {
        dirent* const entry = readdir(stream);
        if (entry == nullptr) {
            if (errno != 0) valid = false;
            break;
        }
        int descriptor = -1;
        const char* const begin = entry->d_name;
        const char* const end = begin + std::strlen(begin);
        const auto parsed = std::from_chars(begin, end, descriptor);
        if (parsed.ec != std::errc{} || parsed.ptr != end || descriptor < 0 || descriptor == own)
            continue;
        struct stat status{};
        std::array<char, 512> link{};
        const ssize_t count = readlinkat(own, entry->d_name, link.data(), link.size());
        if (fstat(descriptor, &status) != 0 || count < 0 ||
            static_cast<std::size_t>(count) == link.size()) {
            valid = false;
            break;
        }
        std::string identity = std::to_string(status.st_dev) + ":" + std::to_string(status.st_ino) +
                               ":" + std::to_string(status.st_mode) + ":" +
                               std::string(link.data(), static_cast<std::size_t>(count));
        if (!result.emplace(descriptor, std::move(identity)).second) valid = false;
        errno = 0;
    }
    const int read_error = errno;
    const bool closed = closedir(stream) == 0;
    if (!valid || read_error != 0 || !closed) result.clear();
    return valid && read_error == 0 && closed;
}

bool absent(int directory_fd, const char* name) {
    struct stat status{};
    errno = 0;
    return fstatat(directory_fd, name, &status, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
}

std::string exact_source(std::uint16_t port) {
    return "listen :" + std::to_string(port) + "\nroute GET \"/\" { return 204 }\n";
}

bool source_failed(const source::Diagnostic& diagnostic,
                   source::FailurePhase phase,
                   int error_number) {
    return diagnostic.phase == phase && diagnostic.error_number == error_number;
}

bool make_directory(directory::PrivateDirectoryLease& lease, directory::Diagnostic& diagnostic) {
    return directory::PrivateDirectoryLease::create(lease, diagnostic);
}

bool clean_source_and_directory(source::WildcardAttemptSourceLease& source_lease,
                                directory::PrivateDirectoryLease& directory_lease) {
    source::Diagnostic source_diagnostic;
    directory::Diagnostic directory_diagnostic;
    return source_lease.remove(source_diagnostic) &&
           source_lease.state() == source::State::Removed &&
           source_lease.cleanup_state()->attempted && source_lease.cleanup_state()->succeeded &&
           absent(directory_lease.descriptor(), kBasename) &&
           directory_lease.settle(directory_diagnostic);
}

bool canonical_sequence(std::uint32_t address) {
    Snapshot before;
    Snapshot after;
    reservation::ExactTcpReservationLease reservation_lease;
    source::WildcardAttemptSourceLease source_lease;
    directory::PrivateDirectoryLease directory_lease;
    reservation::Diagnostic reservation_diagnostic;
    source::Diagnostic source_diagnostic;
    directory::Diagnostic directory_diagnostic;
    bool ok = snapshot(before) && make_directory(directory_lease, directory_diagnostic) &&
              source::WildcardAttemptSourceLease::stage(directory_lease.descriptor(),
                                                        directory_lease.path(),
                                                        kBasename,
                                                        source_lease,
                                                        source_diagnostic) &&
              source_lease.state() == source::State::Staged && !source_lease.active() &&
              reservation::ExactTcpReservationLease::reserve(
                  address, reservation_lease, reservation_diagnostic);
    const auto held_baseline = reservation_lease.baseline();
    const auto identity = source_lease.source_identity();
    ok = ok && reservation_lease.revalidate(reservation_diagnostic) &&
         source_lease.finalize_exact_bytes(exact_source(reservation_lease.port()),
                                           source_diagnostic) &&
         source_lease.active() && source_lease.state() == source::State::Active &&
         source_lease.source_identity().device == identity.device &&
         source_lease.source_identity().inode == identity.inode &&
         source_lease.revalidate(source_diagnostic) &&
         reservation_lease.baseline() == held_baseline &&
         reservation_lease.revalidate(reservation_diagnostic) &&
         reservation_lease.release(reservation_diagnostic) &&
         source_lease.revalidate(source_diagnostic) &&
         clean_source_and_directory(source_lease, directory_lease) && snapshot(after) &&
         before == after;
    return check(ok, "canonical pre-G stage, Held finalize, release and ordered residue");
}

bool argument_retry() {
    source::WildcardAttemptSourceLease source_lease;
    directory::PrivateDirectoryLease directory_lease;
    directory::Diagnostic directory_diagnostic;
    source::Diagnostic diagnostic;
    std::string oversized(256u, 'x');
    const std::string nul("a\0b", 3u);
    bool ok = make_directory(directory_lease, directory_diagnostic) &&
              source::WildcardAttemptSourceLease::stage(directory_lease.descriptor(),
                                                        directory_lease.path(),
                                                        kBasename,
                                                        source_lease,
                                                        diagnostic) &&
              !source_lease.finalize_exact_bytes("", diagnostic) &&
              source_failed(diagnostic, source::FailurePhase::Argument, EINVAL) &&
              source_lease.state() == source::State::Staged &&
              !source_lease.finalize_exact_bytes(oversized, diagnostic) &&
              source_lease.state() == source::State::Staged &&
              !source_lease.finalize_exact_bytes(nul, diagnostic) &&
              source_lease.state() == source::State::Staged &&
              source_lease.finalize_exact_bytes("listen :1\n", diagnostic) &&
              source_lease.revalidate(diagnostic) &&
              !source_lease.finalize_exact_bytes("listen :2\n", diagnostic) &&
              source_failed(diagnostic, source::FailurePhase::State, EALREADY) &&
              source_lease.remove(diagnostic) &&
              !source_lease.finalize_exact_bytes("listen :3\n", diagnostic) &&
              source_failed(diagnostic, source::FailurePhase::State, EALREADY) &&
              directory_lease.settle(directory_diagnostic);
    return check(ok, "pure argument retry and duplicate finalization rejection");
}

enum class Fault {
    None,
    InitialTruncate,
    FinalTruncate,
    PartialHardWrite,
    ZeroWrite,
    HardWrite,
    Sync
};
struct OperationContext {
    Fault fault = Fault::None;
    unsigned truncate_calls = 0u;
    unsigned write_calls = 0u;
    bool offset_prepared = false;
    bool offset_unchanged = false;
};

void prepare_writer_offset(int, const char*, int writer, int, void* opaque) {
    auto& context = *static_cast<OperationContext*>(opaque);
    context.offset_prepared = lseek(writer, 7, SEEK_SET) == 7;
}

void observe_writer_offset(int, const char*, int writer, int, void* opaque) {
    auto& context = *static_cast<OperationContext*>(opaque);
    context.offset_unchanged = lseek(writer, 0, SEEK_CUR) == 7;
}

int fault_truncate(int fd, off_t length, void* opaque) {
    auto& context = *static_cast<OperationContext*>(opaque);
    ++context.truncate_calls;
    if ((context.fault == Fault::InitialTruncate && context.truncate_calls == 1u) ||
        (context.fault == Fault::FinalTruncate && context.truncate_calls == 2u)) {
        errno = EIO;
        return -1;
    }
    return ftruncate(fd, length);
}

ssize_t fault_pwrite(int fd, const void* buffer, std::size_t count, off_t offset, void* opaque) {
    auto& context = *static_cast<OperationContext*>(opaque);
    ++context.write_calls;
    if (context.fault == Fault::ZeroWrite) return 0;
    if (context.fault == Fault::HardWrite ||
        (context.fault == Fault::PartialHardWrite && context.write_calls == 3u)) {
        errno = EIO;
        return -1;
    }
    if (context.write_calls == 1u) {
        errno = EINTR;
        return -1;
    }
    const std::size_t bounded = context.write_calls == 2u && count > 1u ? count / 2u : count;
    return pwrite(fd, buffer, bounded, offset);
}

int fault_sync(int fd, void* opaque) {
    auto& context = *static_cast<OperationContext*>(opaque);
    if (context.fault == Fault::Sync) {
        errno = EIO;
        return -1;
    }
    return fsync(fd);
}

bool operation_case(Fault fault, bool expect_success) {
    source::WildcardAttemptSourceLease source_lease;
    directory::PrivateDirectoryLease directory_lease;
    directory::Diagnostic directory_diagnostic;
    source::Diagnostic diagnostic;
    OperationContext context{fault};
    source::StagedSourceHooksForTesting hooks;
    hooks.before_finalize_identity = prepare_writer_offset;
    hooks.after_finalize_sync = observe_writer_offset;
    hooks.ftruncate_operation = fault_truncate;
    hooks.pwrite_operation = fault_pwrite;
    hooks.fsync_operation = fault_sync;
    hooks.context = &context;
    bool ok = make_directory(directory_lease, directory_diagnostic) &&
              source::WildcardAttemptSourceLease::stage_with_hooks_for_testing(
                  directory_lease.descriptor(),
                  directory_lease.path(),
                  kBasename,
                  hooks,
                  source_lease,
                  diagnostic);
    const bool finalized = ok && source_lease.finalize_exact_bytes("listen :8\n", diagnostic);
    ok = ok && context.offset_prepared && finalized == expect_success &&
         source_lease.state() ==
             (expect_success ? source::State::Active : source::State::FinalizeFailed) &&
         (expect_success ? context.offset_unchanged : true) &&
         (expect_success ? source_lease.revalidate(diagnostic)
                         : (!source_lease.finalize_exact_bytes("listen :9\n", diagnostic) &&
                            source_failed(diagnostic, source::FailurePhase::State, EALREADY))) &&
         clean_source_and_directory(source_lease, directory_lease);
    return ok;
}

bool operation_failures() {
    const bool ok =
        operation_case(Fault::None, true) && operation_case(Fault::InitialTruncate, false) &&
        operation_case(Fault::FinalTruncate, false) &&
        operation_case(Fault::PartialHardWrite, false) && operation_case(Fault::ZeroWrite, false) &&
        operation_case(Fault::HardWrite, false) && operation_case(Fault::Sync, false);
    return check(ok, "EINTR/partial completion and terminal syscall failures");
}

enum class Mutation { ModeBefore, SizeAfter, PathAfter, ReaderAfter, WriterAfter };
struct MutationContext {
    Mutation mutation = Mutation::ModeBefore;
    int saved = -1;
    int foreign = -1;
    int owned_slot = -1;
    bool changed = false;
};

void mutate_before(int directory_fd, const char* basename, int writer, int reader, void* opaque) {
    auto& context = *static_cast<MutationContext*>(opaque);
    if (context.mutation == Mutation::ModeBefore)
        context.changed = fchmodat(directory_fd, basename, 0640, 0) == 0;
    else if (context.mutation == Mutation::ReaderAfter ||
             context.mutation == Mutation::WriterAfter) {
        context.owned_slot = context.mutation == Mutation::ReaderAfter ? reader : writer;
        context.saved = fcntl(context.owned_slot, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    }
}

void mutate_after(int directory_fd, const char* basename, int writer, int reader, void* opaque) {
    auto& context = *static_cast<MutationContext*>(opaque);
    if (context.mutation == Mutation::SizeAfter)
        context.changed = ftruncate(writer, 1) == 0;
    else if (context.mutation == Mutation::PathAfter)
        context.changed = renameat(directory_fd, basename, directory_fd, "owned.saved") == 0 &&
                          renameat(directory_fd, "foreign", directory_fd, basename) == 0;
    else if (context.mutation == Mutation::ReaderAfter)
        context.changed = context.saved >= 0 && dup3(context.foreign, reader, O_CLOEXEC) == reader;
    else if (context.mutation == Mutation::WriterAfter)
        context.changed = context.saved >= 0 && dup3(context.foreign, writer, O_CLOEXEC) == writer;
}

bool mutation_case(Mutation mutation) {
    source::WildcardAttemptSourceLease source_lease;
    directory::PrivateDirectoryLease directory_lease;
    directory::Diagnostic directory_diagnostic;
    source::Diagnostic diagnostic;
    MutationContext context{mutation};
    source::StagedSourceHooksForTesting hooks;
    hooks.before_finalize_identity = mutate_before;
    hooks.after_finalize_sync = mutate_after;
    hooks.context = &context;
    bool ok = make_directory(directory_lease, directory_diagnostic);
    if (ok && mutation == Mutation::PathAfter) {
        const int foreign = openat(
            directory_lease.descriptor(), "foreign", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        ok = foreign >= 0 && close(foreign) == 0;
    }
    ok = ok && source::WildcardAttemptSourceLease::stage_with_hooks_for_testing(
                   directory_lease.descriptor(),
                   directory_lease.path(),
                   kBasename,
                   hooks,
                   source_lease,
                   diagnostic);
    if (ok && (mutation == Mutation::ReaderAfter || mutation == Mutation::WriterAfter)) {
        const int access = mutation == Mutation::ReaderAfter ? O_RDONLY : O_WRONLY;
        context.foreign = open("/dev/null", access | O_CLOEXEC);
    }
    const bool finalized = ok && source_lease.finalize_exact_bytes("listen :7\n", diagnostic);
    ok = ok && !finalized && context.changed &&
         source_lease.state() == source::State::FinalizeFailed;
    if (mutation == Mutation::ModeBefore)
        ok = ok && fchmodat(directory_lease.descriptor(), kBasename, 0600, 0) == 0;
    else if (mutation == Mutation::SizeAfter)
        ok = ok && ftruncate(source_lease.descriptor(), 10) != 0 && errno == EINVAL;
    else if (mutation == Mutation::PathAfter)
        ok =
            ok &&
            renameat(
                directory_lease.descriptor(), kBasename, directory_lease.descriptor(), "foreign") ==
                0 &&
            renameat(directory_lease.descriptor(),
                     "owned.saved",
                     directory_lease.descriptor(),
                     kBasename) == 0 &&
            unlinkat(directory_lease.descriptor(), "foreign", 0) == 0;
    if (mutation == Mutation::ReaderAfter || mutation == Mutation::WriterAfter) {
        ok = ok && fcntl(context.foreign, F_GETFD) >= 0 && context.saved >= 0 &&
             dup3(context.saved, context.owned_slot, O_CLOEXEC) == context.owned_slot &&
             close(context.saved) == 0 && close(context.foreign) == 0;
    }
    return ok && clean_source_and_directory(source_lease, directory_lease);
}

bool mutation_failures() {
    const bool ok = mutation_case(Mutation::ModeBefore) && mutation_case(Mutation::SizeAfter) &&
                    mutation_case(Mutation::PathAfter) && mutation_case(Mutation::ReaderAfter) &&
                    mutation_case(Mutation::WriterAfter);
    return check(ok, "pre-write identity and postverify mutations are terminal");
}

struct WriterCapture {
    int descriptor = -1;
};
void capture_writer(int, const char*, int writer, int, void* opaque) {
    static_cast<WriterCapture*>(opaque)->descriptor = writer;
}

bool active_mutation_and_destructors() {
    bool ok = true;
    {
        source::WildcardAttemptSourceLease source_lease;
        directory::PrivateDirectoryLease directory_lease;
        directory::Diagnostic directory_diagnostic;
        source::Diagnostic diagnostic;
        WriterCapture capture;
        source::StagedSourceHooksForTesting hooks;
        hooks.before_finalize_identity = capture_writer;
        hooks.context = &capture;
        const std::string bytes = "listen :6\n";
        ok = make_directory(directory_lease, directory_diagnostic) &&
             source::WildcardAttemptSourceLease::stage_with_hooks_for_testing(
                 directory_lease.descriptor(),
                 directory_lease.path(),
                 kBasename,
                 hooks,
                 source_lease,
                 diagnostic) &&
             source_lease.finalize_exact_bytes(bytes, diagnostic) && capture.descriptor >= 0 &&
             ftruncate(capture.descriptor, static_cast<off_t>(bytes.size() - 1u)) == 0 &&
             !source_lease.revalidate(diagnostic) &&
             source_failed(diagnostic, source::FailurePhase::Lease, ESTALE) &&
             pwrite(capture.descriptor,
                    bytes.data() + bytes.size() - 1u,
                    1u,
                    static_cast<off_t>(bytes.size() - 1u)) == 1 &&
             ftruncate(capture.descriptor, static_cast<off_t>(bytes.size())) == 0 &&
             fsync(capture.descriptor) == 0 && source_lease.revalidate(diagnostic) &&
             clean_source_and_directory(source_lease, directory_lease);
    }
    for (const bool fail_finalize : {false, true}) {
        directory::PrivateDirectoryLease directory_lease;
        directory::Diagnostic directory_diagnostic;
        std::shared_ptr<const source::CleanupState> cleanup;
        if (!make_directory(directory_lease, directory_diagnostic)) return false;
        {
            source::WildcardAttemptSourceLease source_lease;
            source::Diagnostic diagnostic;
            OperationContext context{Fault::ZeroWrite};
            source::StagedSourceHooksForTesting hooks;
            hooks.pwrite_operation = fault_pwrite;
            hooks.context = &context;
            ok = ok && source::WildcardAttemptSourceLease::stage_with_hooks_for_testing(
                           directory_lease.descriptor(),
                           directory_lease.path(),
                           kBasename,
                           hooks,
                           source_lease,
                           diagnostic);
            if (fail_finalize)
                ok = ok && !source_lease.finalize_exact_bytes("listen :5\n", diagnostic) &&
                     source_lease.state() == source::State::FinalizeFailed;
            cleanup = source_lease.cleanup_state();
        }
        ok = ok && cleanup && cleanup->attempted && cleanup->succeeded &&
             absent(directory_lease.descriptor(), kBasename) &&
             directory_lease.settle(directory_diagnostic);
    }
    return check(ok, "Active mutation and staged/failed destructor cleanup");
}

struct CloseContext {
    bool injected = false;
};
int close_with_eio(int descriptor, void* opaque) {
    auto& context = *static_cast<CloseContext*>(opaque);
    const int result = close(descriptor);
    if (result != 0 || context.injected) return result;
    context.injected = true;
    errno = EIO;
    return -1;
}

bool cleanup_and_legacy() {
    Snapshot process_baseline;
    Snapshot before;
    Snapshot staged;
    Snapshot after;
    bool ok = snapshot(process_baseline);
    {
        source::WildcardAttemptSourceLease source_lease;
        directory::PrivateDirectoryLease directory_lease;
        directory::Diagnostic directory_diagnostic;
        source::Diagnostic diagnostic;
        CloseContext context;
        source::StagedSourceHooksForTesting hooks;
        hooks.close_operation = close_with_eio;
        hooks.context = &context;
        ok = ok && make_directory(directory_lease, directory_diagnostic) &&
             source::WildcardAttemptSourceLease::stage_with_hooks_for_testing(
                 directory_lease.descriptor(),
                 directory_lease.path(),
                 kBasename,
                 hooks,
                 source_lease,
                 diagnostic) &&
             !source_lease.remove(diagnostic) && context.injected &&
             source_failed(diagnostic, source::FailurePhase::Close, EIO) &&
             source_lease.state() == source::State::Removed &&
             source_lease.cleanup_state()->attempted && !source_lease.cleanup_state()->succeeded &&
             absent(directory_lease.descriptor(), kBasename) &&
             directory_lease.settle(directory_diagnostic);
    }
    ok = ok && snapshot(after) && process_baseline == after;
    {
        source::WildcardAttemptSourceLease source_lease;
        directory::PrivateDirectoryLease directory_lease;
        directory::Diagnostic directory_diagnostic;
        source::Diagnostic diagnostic;
        ok = ok && make_directory(directory_lease, directory_diagnostic) && snapshot(before) &&
             source::WildcardAttemptSourceLease::create_exact_bytes(directory_lease.descriptor(),
                                                                    directory_lease.path(),
                                                                    kBasename,
                                                                    "listen :1\n",
                                                                    source_lease,
                                                                    diagnostic) &&
             snapshot(staged) && staged.size() == before.size() + 2u &&
             (fcntl(source_lease.descriptor(), F_GETFL) & O_ACCMODE) == O_RDONLY &&
             source_lease.remove(diagnostic) && directory_lease.settle(directory_diagnostic);
    }
    return check(ok && snapshot(after) && process_baseline == after,
                 "close uncertainty retained and legacy two-FD footprint unchanged");
}

}  // namespace

int main() {
    std::vector<std::uint32_t> addresses;
    reservation::Diagnostic diagnostic;
    if (!reservation::discover_eligible_ipv4(addresses, diagnostic) || addresses.empty()) return 77;
    const bool ok = canonical_sequence(addresses.front()) && argument_retry() &&
                    operation_failures() && mutation_failures() &&
                    active_mutation_and_destructors() && cleanup_and_legacy();
    if (ok) std::puts("PASS: staged wildcard source/reservation sequence");
    return ok ? 0 : 1;
}
