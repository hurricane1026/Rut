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

#include "rut/runtime/arena.h"

#include "rut/runtime/slice_pool.h"

namespace rut {

u8* SlicePoolBackend::acquire(u64 needed, u64* out_size) {
    if (!pool) return nullptr;
    if (needed > SlicePool::kSliceSize) return nullptr;  // won't fit in one slice
    u8* slice = pool->alloc();
    if (!slice) return nullptr;
    *out_size = SlicePool::kSliceSize;
    return slice;
}

void SlicePoolBackend::release(u8* ptr, u64 /*size*/) {
    if (pool) pool->free(ptr);
}

}  // namespace rut
