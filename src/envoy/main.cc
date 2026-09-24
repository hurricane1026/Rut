#include "rut/envoy/converter.h"
#include "rut/envoy/parser.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr size_t kMaxInputBytes = size_t{1024u} * size_t{1024u};

bool write_all(int fd, const char* data, size_t length) {
    size_t offset = 0u;
    while (offset < length) {
        const ssize_t written = write(fd, data + offset, length - offset);
        if (written > 0) {
            offset += static_cast<size_t>(written);
            continue;
        }
        if (written < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool write_cstr(int fd, const char* text) {
    return write_all(fd, text, strlen(text));
}

// `struct stat`'s nanosecond mtime/ctime fields are named `st_mtim`/`st_ctim`
// on Linux (glibc, POSIX.1-2008) but `st_mtimespec`/`st_ctimespec` on Apple's
// Darwin `<sys/stat.h>` (macOS `stat(2)` man page: "For compatibility with
// previous versions of this interface, the times are also available under
// the names st_atimespec, st_mtimespec and st_ctimespec"); both are
// `struct timespec`. These accessors hide the name difference so the TOCTOU
// check below compares the same fields on every supported platform without
// weakening it.
const struct timespec& mtime_of(const struct stat& info) {
#ifdef __APPLE__
    return info.st_mtimespec;
#else
    return info.st_mtim;
#endif
}

const struct timespec& ctime_of(const struct stat& info) {
#ifdef __APPLE__
    return info.st_ctimespec;
#else
    return info.st_ctim;
#endif
}

void report(const char* filename, rut::Span span, rut::Str detail, const char* fallback) {
    write_cstr(STDERR_FILENO, filename);
    char coordinates[96];
    const int length = snprintf(coordinates,
                                sizeof(coordinates),
                                ":%u:%u: ",
                                span.line == 0u ? 1u : span.line,
                                span.col == 0u ? 1u : span.col);
    if (length > 0) {
        const size_t bounded = static_cast<size_t>(length) < sizeof(coordinates)
                                   ? static_cast<size_t>(length)
                                   : sizeof(coordinates) - 1u;
        write_all(STDERR_FILENO, coordinates, bounded);
    }
    if (detail.ptr != nullptr && detail.len != 0u)
        write_all(STDERR_FILENO, detail.ptr, detail.len);
    else
        write_cstr(STDERR_FILENO, fallback);
    write_cstr(STDERR_FILENO, "\n");
}

int input_error(const char* filename, const char* detail) {
    report(filename, {}, {}, detail);
    return 1;
}

// Fixed-size, statically-allocated (BSS) input buffer: this CLI converts
// exactly one bootstrap document per invocation, so there is no lifetime or
// reentrancy concern that would call for a heap allocator, and the 1 MiB
// limit below is exactly `kMaxInputBytes`. Using `static` storage instead of
// `malloc` keeps this file within the project's no-`new`/no-`malloc` rule
// (AGENTS.md, "core constraints") the same way `main()` already does for
// `doc` and `output` below.
static char g_input_buffer[kMaxInputBytes + 1u];

// PR #692 round-8 review: second, independent read used to verify the first
// one below (`read_input`'s content re-check) — see the round-8 comment
// there for why a metadata-only comparison is not sufficient. Same
// static-storage rationale as `g_input_buffer` above.
static char g_verify_buffer[kMaxInputBytes + 1u];

// Reads the whole of `fd` from offset 0 into `buffer` (capacity `capacity`),
// the same loop shape `read_input` used inline before round-8 split it out
// so both the primary read and the round-8 content-verification re-read
// share one implementation. Uses `pread` (not the shared file offset) so a
// second call starts at byte 0 regardless of where the first left the
// offset.
bool read_whole_file(int fd, char* buffer, size_t capacity, size_t* out_used, const char** error) {
    size_t used = 0u;
    for (;;) {
        const ssize_t count = pread(fd, buffer + used, capacity - used, static_cast<off_t>(used));
        if (count > 0) {
            used += static_cast<size_t>(count);
            if (used > kMaxInputBytes) {
                *error = "input exceeds the 1 MiB limit";
                return false;
            }
            continue;
        }
        if (count == 0) break;
        if (errno == EINTR) continue;
        *error = strerror(errno);
        return false;
    }
    *out_used = used;
    return true;
}

bool read_input(const char* filename, char** output, size_t* length, const char** error) {
    *output = nullptr;
    *length = 0u;
    *error = nullptr;

    const int fd = open(filename, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        *error = strerror(errno);
        return false;
    }
    struct stat before{};
    if (fstat(fd, &before) != 0) {
        *error = strerror(errno);
        close(fd);
        return false;
    }
    if (!S_ISREG(before.st_mode)) {
        *error = "input is not a regular file";
        close(fd);
        return false;
    }
    if (before.st_size < 0 || static_cast<uintmax_t>(before.st_size) > kMaxInputBytes) {
        *error = "input exceeds the 1 MiB limit";
        close(fd);
        return false;
    }

    char* const buffer = g_input_buffer;
    size_t used = 0u;
    if (!read_whole_file(fd, buffer, sizeof(g_input_buffer), &used, error)) {
        close(fd);
        return false;
    }
    struct stat after{};
    if (fstat(fd, &after) != 0) {
        *error = strerror(errno);
        close(fd);
        return false;
    }
    // PR #692 round-3 review: comparing only `after.st_size` to `used` (the
    // byte count this call actually read) does not detect an in-place
    // rewrite that keeps the file's length unchanged — another process can
    // overwrite the file with different content of the same size while this
    // loop is mid-read, and the size-only check above would still pass,
    // silently admitting a torn mix of the old and new bytes (e.g. a
    // listener from one revision combined with an endpoint from another).
    // Comparing every field `write()`/`rename()`-free in-place rewrites are
    // expected to change — device, inode, size, and the nanosecond mtime/ctime
    // pair — catches that case: an in-place rewrite that lands entirely
    // between `before` and this `after` snapshot always advances the file's
    // mtime/ctime, even when it leaves the length identical, and a
    // replace-via-rename changes the inode. Kept as a cheap pre-check (fails
    // fast, no second read needed) ahead of the round-8 content check below,
    // which is what actually proves the bytes are stable.
    if (after.st_size < 0 || static_cast<uintmax_t>(after.st_size) != used ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || mtime_of(before).tv_sec != mtime_of(after).tv_sec ||
        mtime_of(before).tv_nsec != mtime_of(after).tv_nsec ||
        ctime_of(before).tv_sec != ctime_of(after).tv_sec ||
        ctime_of(before).tv_nsec != ctime_of(after).tv_nsec) {
        *error = "input changed while it was being read";
        close(fd);
        return false;
    }
    // PR #692 round-8 review: identical device/inode/size/mtime/ctime is not
    // proof the content is stable. A same-size in-place rewrite through an
    // existing shared mapping (mmap + memcpy, no write()/rename()) need not
    // touch any of those fields at all, and even an ordinary write()-based
    // rewrite can land twice within the filesystem timestamp's granularity
    // and still leave `before`/`after` identical. Because the read loop
    // above and either of those writes are not a single atomic operation,
    // the buffer can still contain pages from two different revisions and,
    // if that torn mixture happens to be valid JSON, lower successfully.
    // Re-reading the whole file into a second, independent buffer and
    // requiring exact byte-for-byte equality (not just equal length) with
    // the first read is a real content check: any change that lands between
    // the start of the first read and the end of the second — including a
    // writer that was mid-rewrite during the first read and has progressed
    // since — makes the two reads disagree somewhere, and two consecutive
    // reads that agree everywhere are the closest thing to a stable snapshot
    // available without an explicit lock (`flock`) or copy-on-write snapshot
    // the target filesystem may not support.
    //
    // PR #692 CI (Sanitizer job): what this cannot do is tell a file that
    // *holds* a torn mixture for the whole read window from one that simply
    // contains those bytes. An in-place `write()` copies into the page cache
    // one page at a time with no lock against buffered reads (ext4, tmpfs)
    // and bumps mtime/ctime before the first page, so a writer preempted
    // mid-copy leaves the file torn with its final timestamps already set;
    // a run that fits inside that stall reads the torn bytes twice,
    // identically, and converts them as the input (docs/envoy-converter.md,
    // "Input format"). Writers must replace the file atomically (write a
    // temporary, then `rename()`) for the converter to see only whole
    // revisions.
    size_t verify_used = 0u;
    if (!read_whole_file(fd, g_verify_buffer, sizeof(g_verify_buffer), &verify_used, error)) {
        close(fd);
        return false;
    }
    const int close_result = close(fd);
    if (close_result != 0) {
        *error = strerror(errno);
        return false;
    }
    if (verify_used != used || memcmp(buffer, g_verify_buffer, used) != 0) {
        *error = "input changed while it was being read";
        return false;
    }
    // PR #692 round-15 review: rereading the same descriptor twice (the
    // round-8 check above) cannot observe a writer that publishes via
    // `rename(tmp, filename)` — the atomic-replace model
    // docs/envoy-converter.md's "Input format" already asks writers to use.
    // A rename swaps what the pathname `filename` resolves to without
    // touching the already-open descriptor `fd` at all, so both `pread`s and
    // both `fstat`s above keep inspecting the original (now
    // unlinked-but-still-open) file and see it completely unchanged, even
    // though the documented rename-replace case happened during this read.
    // `stat()` — not `lstat()`, matching `open()`'s own symlink-following
    // behavior — resolves `filename` fresh, after every read and the
    // descriptor's close are done, and a device/inode mismatch against the
    // descriptor's own `after` fstat above is exactly that replacement.
    struct stat path_after{};
    if (stat(filename, &path_after) != 0) {
        *error = strerror(errno);
        return false;
    }
    if (path_after.st_dev != after.st_dev || path_after.st_ino != after.st_ino) {
        *error = "input changed while it was being read";
        return false;
    }
    *output = buffer;
    *length = used;
    return true;
}

// D2 (docs/envoy-compatibility.md, "Blocked by Rut"): Envoy's `connect_timeout`
// is optional at the proto level (default 5s), but this frontend's parser
// (increment 1) requires it present and positive, so a bootstrap that reaches
// this point always carries one. Rut has no connect-establishment timeout
// surface at all — the fixed 30s `kDefaultUpstreamTimeout`
// (include/rut/runtime/event_loop.h) bounds time from connect completion to
// the first response byte, not TCP connect establishment — so rejecting
// every input that carries `connect_timeout` would make the milestone
// unreachable while fixing nothing. Accept, but say so on stderr.
void warn_connect_timeout(rut::Str timeout_text) {
    write_cstr(STDERR_FILENO, "warning: connect_timeout \"");
    if (timeout_text.ptr != nullptr && timeout_text.len != 0u)
        write_all(STDERR_FILENO, timeout_text.ptr, timeout_text.len);
    write_cstr(STDERR_FILENO,
               "\" has no Rut runtime equivalent (no per-upstream connect-establishment "
               "timeout surface); the value is accepted but not enforced\n");
}

// PR #692 round-7 review: an Envoy HCM with `codec_type: "HTTP1"` (required
// by the parser, see include/rut/envoy/parser.h) rejects a client that opens
// with the h2c connection preface before routing; the emitted Rut `listen`
// has no protocol knob and always recognizes the preface and upgrades
// (`on_header_received`, include/rut/runtime/callbacks_impl.h). This is not
// gated behind a `RutCapabilities` flag: doing so would fail closed on every
// milestone bootstrap over a per-connection client shape, not a
// configuration Rut cannot express (docs/envoy-compatibility.md,
// "HTTP1-only HCM rejects a client that opens with the h2c connection
// preface", already `BLOCKED_BY_RUT`). Accept, but say so on stderr, the
// same way `warn_connect_timeout` above does for its own gap.
void warn_h2c_preface() {
    write_cstr(STDERR_FILENO, rut::envoy::kH2cPrefaceWarningText);
}

int usage(const char* program) {
    write_cstr(STDERR_FILENO, "usage: ");
    write_cstr(STDERR_FILENO, program);
    write_cstr(STDERR_FILENO, " --format bootstrap-json <input-file>\n");
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    struct sigaction ignore{};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    if (sigaction(SIGPIPE, &ignore, nullptr) != 0) {
        return input_error(argc > 0 && argv[0] != nullptr ? argv[0] : "rut-envoy-convert",
                           "could not ignore SIGPIPE");
    }

    if (argc != 4 || strcmp(argv[1], "--format") != 0 || strcmp(argv[2], "bootstrap-json") != 0)
        return usage(argv[0]);

    char* input = nullptr;
    size_t input_length = 0u;
    const char* read_error = nullptr;
    if (!read_input(argv[3], &input, &input_length, &read_error))
        return input_error(argv[3], read_error == nullptr ? "input read failed" : read_error);

    const rut::Str source{input, static_cast<rut::u32>(input_length)};
    static rut::envoy::JsonDocument doc;
    const auto parsed = rut::envoy::parse_bootstrap_json(source, doc);
    if (!parsed) {
        report(argv[3], parsed.error().span, parsed.error().detail, "conversion failed");
        return 1;
    }

    const auto lowered = rut::envoy::lower_to_rut(parsed.value());
    if (!lowered) {
        report(argv[3], lowered.error().span, lowered.error().detail, "conversion failed");
        return 1;
    }
    warn_connect_timeout(parsed.value().clusters[0].connect_timeout.text);
    if (rut::envoy::needs_h2c_preface_warning(parsed.value())) warn_h2c_preface();

    static rut::envoy::RutSource output;
    output = lowered.value();
    const rut::Str view = output.view();
    const bool wrote = write_all(STDOUT_FILENO, view.ptr, view.len);
    const int output_errno = wrote ? 0 : errno;
    if (!wrote) {
        char output_error[128];
        snprintf(output_error,
                 sizeof(output_error),
                 "output write failed: %s",
                 output_errno == 0 ? "unknown error" : strerror(output_errno));
        report("stdout", {}, {}, output_error);
        return 1;
    }
    return 0;
}
