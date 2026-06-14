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

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"

namespace rut {

// Create a non-blocking, reusable listen socket.
// Returns fd on success, Error on failure.
// Uses SO_REUSEPORT so each shard can bind the same port.
core::Expected<i32, Error> create_listen_socket(u16 port);

// Set fd to non-blocking mode.
core::Expected<void, Error> set_nonblocking(i32 fd);

}  // namespace rut
