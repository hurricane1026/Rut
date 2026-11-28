#pragma once

#include <errno.h>
#include <unistd.h>

namespace rut::testing {

inline void write_stdout(const char* data, size_t size) {
    while (size != 0) {
        const ssize_t written = ::write(STDOUT_FILENO, data, size);
        if (written > 0) {
            data += written;
            size -= written;
        } else if (written == 0 || errno != EINTR) {
            return;
        }
    }
}

}  // namespace rut::testing
