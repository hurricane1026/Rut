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

#pragma once

#include "rut/common/types.h"

#include <openssl/base.h>

namespace rut {

// Runtime-private seam for forcing specific TLS state-machine transitions in
// epoll tests. Production code always uses the default OpenSSL/BoringSSL hooks.
struct EpollTlsHooks {
    i32 (*ssl_accept)(SSL* ssl);
    i32 (*ssl_read)(SSL* ssl, void* buf, i32 len);
    i32 (*ssl_write)(SSL* ssl, const void* buf, i32 len);
    i32 (*ssl_get_error)(SSL* ssl, i32 rc);
};

}  // namespace rut
