#pragma once

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace rut::platform {

#ifdef __APPLE__
inline constexpr int kSendFlags = 0;
#else
inline constexpr int kSendFlags = MSG_NOSIGNAL;
#endif

inline bool prepare_socket(int fd) {
    const int flags = fcntl(fd, F_GETFL);
    if (flags < 0 ||
        fcntl(fd,
              F_SETFL,
              static_cast<int>(static_cast<unsigned>(flags) | static_cast<unsigned>(O_NONBLOCK))) <
            0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
        return false;
#ifdef __APPLE__
    const int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) < 0) return false;
#endif
    return true;
}

inline int prepare_or_close(int fd) {
    if (fd < 0 || prepare_socket(fd)) return fd;
    const int error = errno;
    close(fd);
    errno = error;
    return -1;
}

inline int stream_socket() {
#ifdef __APPLE__
    return prepare_or_close(socket(AF_INET, SOCK_STREAM, 0));
#else
    return socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#endif
}

inline int accept_nonblocking(int listener) {
#ifdef __APPLE__
    return prepare_or_close(accept(listener, nullptr, nullptr));
#else
    return accept4(listener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
#endif
}

}  // namespace rut::platform
