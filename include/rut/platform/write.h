#pragma once

#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

namespace rut::platform {

[[nodiscard]] inline bool write_all(int fd, const char* data, size_t remaining) {
    while (remaining != 0) {
        const ssize_t written = ::write(fd, data, remaining);
        if (written > 0) {
            data += written;
            remaining -= written;
        } else if (written == 0 || errno != EINTR) {
            return false;
        }
    }
    return true;
}

inline void write_diagnostic(const char* text) {
    if (!write_all(STDERR_FILENO, text, strlen(text))) ::syslog(LOG_USER | LOG_ERR, "%s", text);
}

}  // namespace rut::platform
