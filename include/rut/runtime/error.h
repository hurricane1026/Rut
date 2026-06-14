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

#include <errno.h>

namespace rut {

// Runtime error — carries errno + context about where the error occurred.
// Used as the E type in Expected<T, Error> for init/setup functions.
struct Error {
    i32 code;  // errno value (positive, e.g., ENOMEM=12)

    enum class Source : u8 {
        Mmap,        // mmap failed
        Epoll,       // epoll_create/ctl failed
        IoUring,     // io_uring_setup/register failed
        Timerfd,     // timerfd_create/settime failed
        Socket,      // socket/bind/listen failed
        Thread,      // pthread_create failed
        Arena,       // Arena block allocation failed
        SlicePool,   // SlicePool init failed
        SlabPool,    // SlabPool init failed
        RouteTable,  // RouteTable capacity exceeded
        HttpParser,  // HTTP parse error (invalid input)
    };
    Source source;

    static Error from_errno(Source src) { return {static_cast<i32>(errno), src}; }
    static Error make(i32 code, Source src) { return {code, src}; }
};

}  // namespace rut
