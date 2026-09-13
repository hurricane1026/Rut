#include "rut/runtime/socket.h"

#include "rut/runtime/listener.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

namespace rut {

core::Expected<void, Error> set_nonblocking(i32 fd) {
    i32 flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return core::make_unexpected(Error::from_errno(Error::Source::Socket));
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return core::make_unexpected(Error::from_errno(Error::Source::Socket));
    return {};
}

core::Expected<i32, Error> create_listen_socket(const ListenerSpec& declared, u16 requested_port) {
    if (!declared.valid())
        return core::make_unexpected(Error::make(EAFNOSUPPORT, Error::Source::Socket));
    if (declared.port != 0u && declared.port != requested_port)
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));

    i32 fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return core::make_unexpected(Error::from_errno(Error::Source::Socket));

    i32 one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(requested_port);
    switch (declared.address) {
        case ListenerAddress::IPv4Wildcard:
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            break;
        case ListenerAddress::IPv4Exact:
            addr.sin_addr.s_addr = htonl(declared.ipv4_host);
            break;
    }

    if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        auto err = Error::from_errno(Error::Source::Socket);
        close(fd);
        return core::make_unexpected(err);
    }

    if (listen(fd, 4096) < 0) {
        auto err = Error::from_errno(Error::Source::Socket);
        close(fd);
        return core::make_unexpected(err);
    }

    return fd;
}

core::Expected<i32, Error> create_listen_socket(u16 port) {
    ListenerSpec wildcard{};
    wildcard.port = port;
    return create_listen_socket(wildcard, port);
}

}  // namespace rut
