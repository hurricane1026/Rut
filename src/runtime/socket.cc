/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

#include "rut/runtime/socket.h"

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

core::Expected<i32, Error> create_listen_socket(u16 port) {
    i32 fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return core::make_unexpected(Error::from_errno(Error::Source::Socket));

    i32 one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = __builtin_bswap16(port);  // htons without stdlib
    addr.sin_addr.s_addr = 0;                 // INADDR_ANY

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

}  // namespace rut
