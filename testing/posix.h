#pragma once

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace rut::test {

inline int cloexec_socket(int domain, int type, int protocol) {
#ifdef __linux__
    return socket(domain, type | SOCK_CLOEXEC, protocol);
#else
    const int fd = socket(domain, type, protocol);
    if (fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        const int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
#endif
}

inline int cloexec_accept(int listener) {
#ifdef __linux__
    return accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
#else
    const int fd = accept(listener, nullptr, nullptr);
    if (fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        const int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
#endif
}

inline int nonblocking_pipe(int fds[2]) {
#ifdef __linux__
    return pipe2(fds, O_NONBLOCK | O_CLOEXEC);
#else
    if (pipe(fds) != 0) return -1;
    for (int i = 0; i < 2; ++i) {
        if (fcntl(fds[i], F_SETFL, O_NONBLOCK) < 0 || fcntl(fds[i], F_SETFD, FD_CLOEXEC) < 0) {
            const int error = errno;
            close(fds[0]);
            close(fds[1]);
            fds[0] = fds[1] = -1;
            errno = error;
            return -1;
        }
    }
    return 0;
#endif
}

inline int stream_socketpair(int fds[2]) {
#ifdef __linux__
    return socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds);
#else
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return -1;
    for (int i = 0; i < 2; ++i) {
        if (fcntl(fds[i], F_SETFD, FD_CLOEXEC) < 0) {
            const int error = errno;
            close(fds[0]);
            close(fds[1]);
            fds[0] = fds[1] = -1;
            errno = error;
            return -1;
        }
    }
    return 0;
#endif
}

inline int nonblocking_socketpair(int fds[2]) {
    if (stream_socketpair(fds) != 0) return -1;
    for (int i = 0; i < 2; ++i) {
        if (fcntl(fds[i], F_SETFL, O_NONBLOCK) < 0) {
            const int error = errno;
            close(fds[0]);
            close(fds[1]);
            fds[0] = fds[1] = -1;
            errno = error;
            return -1;
        }
    }
    return 0;
}

}  // namespace rut::test
