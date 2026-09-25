#include "rut/envoy/converter.h"
#include "rut/envoy/parser.h"
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <fcntl.h>
#include <signal.h>
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
    const size_t capacity = sizeof(g_input_buffer);
    size_t used = 0u;
    for (;;) {
        const ssize_t count = read(fd, buffer + used, capacity - used);
        if (count > 0) {
            used += static_cast<size_t>(count);
            if (used > kMaxInputBytes) {
                *error = "input exceeds the 1 MiB limit";
                close(fd);
                return false;
            }
            continue;
        }
        if (count == 0) break;
        if (errno == EINTR) continue;
        *error = strerror(errno);
        close(fd);
        return false;
    }
    struct stat after{};
    if (fstat(fd, &after) != 0) {
        *error = strerror(errno);
        close(fd);
        return false;
    }
    const int close_result = close(fd);
    if (close_result != 0) {
        *error = strerror(errno);
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
    // replace-via-rename changes the inode. This is still not a perfect
    // atomic-snapshot guarantee (a rewrite could in principle restore
    // identical metadata down to the nanosecond), but it closes the concrete
    // same-size gap the review reported, which the size-only check could
    // never see.
    if (after.st_size < 0 || static_cast<uintmax_t>(after.st_size) != used ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
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
    warn_connect_timeout(parsed.value().cluster.connect_timeout.text);

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
