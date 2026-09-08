#include "rut/nginx/converter.h"
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

    const size_t capacity = kMaxInputBytes + 1u;
    char* buffer = static_cast<char*>(malloc(capacity));
    if (buffer == nullptr) {
        *error = "input allocation failed";
        close(fd);
        return false;
    }
    size_t used = 0u;
    for (;;) {
        const ssize_t count = read(fd, buffer + used, capacity - used);
        if (count > 0) {
            used += static_cast<size_t>(count);
            if (used > kMaxInputBytes) {
                *error = "input exceeds the 1 MiB limit";
                free(buffer);
                close(fd);
                return false;
            }
            continue;
        }
        if (count == 0) break;
        if (errno == EINTR) continue;
        *error = strerror(errno);
        free(buffer);
        close(fd);
        return false;
    }
    struct stat after{};
    if (fstat(fd, &after) != 0) {
        *error = strerror(errno);
        free(buffer);
        close(fd);
        return false;
    }
    const int close_result = close(fd);
    if (close_result != 0) {
        *error = strerror(errno);
        free(buffer);
        return false;
    }
    if (after.st_size < 0 || static_cast<uintmax_t>(after.st_size) != used) {
        *error = "input changed while it was being read";
        free(buffer);
        return false;
    }
    *output = buffer;
    *length = used;
    return true;
}

enum class Format : std::uint8_t { Server, Http };

int usage(const char* program) {
    write_cstr(STDERR_FILENO, "usage: ");
    write_cstr(STDERR_FILENO, program);
    write_cstr(STDERR_FILENO, " --format server|http <input-file>\n");
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    struct sigaction ignore{};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    if (sigaction(SIGPIPE, &ignore, nullptr) != 0) {
        return input_error(argc > 0 && argv[0] != nullptr ? argv[0] : "rut-nginx-convert",
                           "could not ignore SIGPIPE");
    }

    if (argc != 4 || strcmp(argv[1], "--format") != 0) return usage(argv[0]);
    Format format;
    if (strcmp(argv[2], "server") == 0)
        format = Format::Server;
    else if (strcmp(argv[2], "http") == 0)
        format = Format::Http;
    else
        return usage(argv[0]);

    char* input = nullptr;
    size_t input_length = 0u;
    const char* read_error = nullptr;
    if (!read_input(argv[3], &input, &input_length, &read_error))
        return input_error(argv[3], read_error == nullptr ? "input read failed" : read_error);

    const rut::Str source{input, static_cast<rut::u32>(input_length)};
    rut::Str output{};
    bool converted = false;
    rut::nginx::RutSource server_output{};
    rut::nginx::HttpProfileRutSource http_output{};
    if (format == Format::Server) {
        const auto parsed = rut::nginx::parse(source);
        if (!parsed) {
            report(argv[3], parsed.error().span, parsed.error().detail, "conversion failed");
            free(input);
            return 1;
        }
        const auto lowered = rut::nginx::lower_to_rut(parsed.value());
        if (!lowered) {
            report(argv[3], lowered.error().span, lowered.error().detail, "conversion failed");
            free(input);
            return 1;
        }
        server_output = lowered.value();
        output = server_output.view();
        converted = true;
    } else {
        const auto parsed = rut::nginx::parse_http_profile(source);
        if (!parsed) {
            report(argv[3], parsed.error().span, parsed.error().detail, "conversion failed");
            free(input);
            return 1;
        }
        const auto lowered = rut::nginx::lower_to_rut(parsed.value());
        if (!lowered) {
            report(argv[3], lowered.error().span, lowered.error().detail, "conversion failed");
            free(input);
            return 1;
        }
        http_output = lowered.value();
        output = http_output.view();
        converted = true;
    }
    const bool wrote = converted && write_all(STDOUT_FILENO, output.ptr, output.len);
    const int output_errno = wrote ? 0 : errno;
    free(input);
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
