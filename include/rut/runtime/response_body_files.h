#pragma once

#include "rut/runtime/route_table.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace rut {
inline void attach_response_body_files(RouteConfig& cfg) {
#ifndef __linux__
    (void)cfg;  // memfd/sendfile are Linux-only; bodies keep memory sends.
#else
    for (u32 i = 0; i < cfg.response_body_count; ++i) {
        auto& body = cfg.response_bodies[i];
        if (body.file_ref != 0 || body.len < RouteConfig::kFileBodyMinLen) continue;
        const int fd = memfd_create("rut-response-body", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (fd < 0) continue;
        u32 done = 0;
        while (done < body.len) {
            const ssize_t n = ::write(fd, body.data + done, body.len - done);
            if (n <= 0) break;
            done += static_cast<u32>(n);
        }
        if (done != body.len ||
            fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL) != 0) {
            ::close(fd);
            continue;
        }
        body.file_ref = static_cast<u32>(fd) + 1u;
    }
#endif
}

inline void close_response_body_files(RouteConfig& cfg) {
    for (u32 i = 0; i < cfg.response_body_count; ++i) {
        auto& body = cfg.response_bodies[i];
        if (body.file_ref == 0) continue;
        ::close(body.file_fd());
        body.file_ref = 0;
    }
}

}  // namespace rut
