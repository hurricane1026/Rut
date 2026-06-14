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

namespace rut {

enum class FrontendError : u8 {
    UnexpectedChar,
    UnterminatedString,
    InvalidInteger,
    UnexpectedToken,
    UnexpectedEof,
    TooManyTokens,
    TooManyItems,
    InvalidStatusCode,
    DuplicateUpstream,
    UnknownUpstream,
    OutOfMemory,
    InvalidRegex,
    UnsupportedSyntax,
};

struct Span {
    u32 start = 0;
    u32 end = 0;
    u32 line = 1;
    u32 col = 1;
};

struct Diagnostic {
    FrontendError code = FrontendError::UnexpectedToken;
    Span span{};
    Str detail{};
};

template <typename T>
using FrontendResult = core::Expected<T, Diagnostic>;

inline auto frontend_error(FrontendError code, Span span = {}, Str detail = {}) {
    return core::make_unexpected(Diagnostic{code, span, detail});
}

}  // namespace rut
